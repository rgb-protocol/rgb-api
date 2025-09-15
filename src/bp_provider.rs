// RGB API library for smart contracts on Bitcoin & Lightning network
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::convert::Infallible;

use bpwallet::psbt::{
    Beneficiary as BpBeneficiary, Output as BpOutput, PropKey, PsbtConstructor,
    PsbtMeta as BpPsbtMeta, TxParams as BpTxParams,
};
use bpwallet::{Address, IdxBase, LockTime, NormalIndex, Psbt as BpPsbt, Sats, SeqNo, Wallet};
use psrgbt::bp_conversion_utils::{
    address_network_bitcoin_to_bp, address_payload_bp_from_script_pubkey, outpoint_bitcoin_to_bp,
    script_buf_to_script_pubkey, txid_bitcoin_to_bp, untweakedpublickey_to_internal_pk,
};
use psrgbt::{RgbOutExt, RgbPsbtExt, Terminal};
use rgbstd::containers::Transfer;
use rgbstd::invoice::{Beneficiary, RgbInvoice};
use rgbstd::rgbcore::commit_verify::mpc::{Message, ProtocolId};
use rgbstd::rgbcore::dbc::tapret::TapretCommitment;
use rgbstd::rgbcore::seals::txout::CloseMethod;
use rgbstd::validation::DbcProof;
use rgbstd::{Operation, Outpoint, Txid};

use super::*;
use crate::pay::{PsbtMeta, TxParams};
use crate::{CompositionError, DescriptorRgb, WalletError};

impl From<BpTxParams> for TxParams {
    fn from(value: BpTxParams) -> Self {
        Self {
            fee_sats: value.fee.sats(),
            lock_time: value.lock_time.map(|l| l.into_consensus_u32()),
            seq_no: value.seq_no.to_consensus_u32(),
            change_shift: value.change_shift,
            change_keychain: value.change_keychain.into(),
        }
    }
}

impl From<TxParams> for BpTxParams {
    fn from(value: TxParams) -> Self {
        Self {
            fee: Sats::from_sats(value.fee_sats),
            lock_time: value.lock_time.map(LockTime::from_consensus_u32),
            seq_no: SeqNo::from_consensus_u32(value.seq_no),
            change_shift: value.change_shift,
            change_keychain: value.change_keychain.into(),
        }
    }
}

impl From<BpPsbtMeta> for PsbtMeta {
    fn from(value: BpPsbtMeta) -> Self {
        Self {
            beneficiary_vout: None,
            change_vout: value.change_vout.map(|v| v.into_u32()),
        }
    }
}

impl<K, D: DescriptorRgb + bpwallet::Descriptor<K>> WalletProvider for Wallet<K, D> {
    type P = PropKey;
    type O = BpOutput;
    type Psbt = BpPsbt;

    fn close_method(&self) -> CloseMethod { self.descriptor().close_method() }

    fn is_unspent(&self, outpoint: Outpoint) -> bool {
        self.is_unspent(outpoint_bitcoin_to_bp(outpoint))
    }

    fn has_outpoint(&self, outpoint: Outpoint) -> bool {
        self.has_outpoint(outpoint_bitcoin_to_bp(outpoint))
    }

    fn should_include_witness(&self, witness_id: Option<Txid>) -> bool {
        let witness_id = witness_id.map(txid_bitcoin_to_bp);
        self.history()
            .any(|row| !row.our_inputs.is_empty() && witness_id == Some(row.txid))
    }

    fn add_tapret_tweak(
        &mut self,
        terminal: Terminal,
        tweak: TapretCommitment,
    ) -> Result<(), Infallible> {
        self.descriptor_mut(|descr| {
            descr.with_descriptor_mut(|d| {
                d.add_tapret_tweak(terminal, tweak);
                Ok::<_, Infallible>(())
            })
        })
    }

    fn try_add_tapret_tweak(
        &mut self,
        transfer: Transfer,
        txid: &Txid,
    ) -> Result<(), Box<WalletError>> {
        let contract_id = transfer.genesis.contract_id();
        for keychain in self.keychains() {
            let last_index = self.next_derivation_index(keychain, false).index() as u16;
            let descr = self.descriptor();
            if let Some((idx, tweak)) = transfer
                .bundles
                .iter()
                .find(|bw| bw.witness_id() == *txid)
                .and_then(|bw| {
                    let bundle_id = bw.bundle().bundle_id();
                    if let DbcProof::Tapret(tapret) = bw.anchor.dbc_proof.clone() {
                        let internal_pk = untweakedpublickey_to_internal_pk(tapret.internal_pk);
                        let commitment = bw
                            .anchor
                            .mpc_proof
                            .clone()
                            .convolve(ProtocolId::from(contract_id), Message::from(bundle_id))
                            .unwrap();
                        let tweak = TapretCommitment::with(commitment, tapret.path_proof.nonce());
                        (0..last_index)
                            .rev()
                            .map(NormalIndex::normal)
                            .find(|i| {
                                descr
                                    .derive(keychain, i)
                                    .any(|ds| ds.to_internal_pk() == Some(internal_pk))
                            })
                            .map(|idx| (idx, tweak))
                    } else {
                        None
                    }
                })
            {
                let terminal = bpwallet::Terminal::new(keychain, idx);
                self.add_tapret_tweak(terminal.into(), tweak).unwrap();
                return Ok(());
            }
        }
        Err(Box::new(WalletError::NoTweakTerminal))
    }

    fn create_psbt(
        &mut self,
        invoice: &RgbInvoice,
        close_method: CloseMethod,
        prev_outpoints: impl IntoIterator<Item = Outpoint>,
        params: TransferParams,
    ) -> Result<(Self::Psbt, PsbtMeta), CompositionError> {
        let (beneficiaries, beneficiary_script) = match invoice.beneficiary.into_inner() {
            Beneficiary::BlindedSeal(_) => (vec![], None),
            Beneficiary::WitnessVout(pay2vout, _) => {
                let script_pubkey = script_buf_to_script_pubkey(pay2vout.to_script());
                let address = Address::new(
                    address_payload_bp_from_script_pubkey(&script_pubkey),
                    address_network_bitcoin_to_bp(invoice.address_network()),
                );
                let bp_beneficiary =
                    BpBeneficiary::new(address, Sats::from_sats(params.min_amount));
                (vec![bp_beneficiary], Some(script_pubkey))
            }
        };

        let prev_outpoints = prev_outpoints
            .into_iter()
            .map(outpoint_bitcoin_to_bp)
            .collect::<Vec<_>>();

        let bp_tx_params: BpTxParams = params.tx.into();
        let (mut psbt, mut meta) =
            self.construct_psbt(prev_outpoints, &beneficiaries, bp_tx_params)?;

        let change_script = meta
            .change_vout
            .and_then(|vout| psbt.output(vout.to_usize()))
            .map(|output| output.script.clone());

        match close_method {
            CloseMethod::TapretFirst => {
                let tap_out_script = if let Some(change_script) = change_script.clone() {
                    psbt.set_rgb_tapret_host_on_change();
                    change_script
                } else {
                    match invoice.beneficiary.into_inner() {
                        Beneficiary::WitnessVout(_, Some(ikey)) => {
                            let beneficiary_script = beneficiary_script.unwrap();
                            let ikey = untweakedpublickey_to_internal_pk(ikey);
                            psbt.outputs_mut()
                                .find(|o| o.script == beneficiary_script)
                                .unwrap()
                                .tap_internal_key = Some(ikey);
                            beneficiary_script
                        }
                        _ => return Err(CompositionError::NoOutputForTapretCommitment),
                    }
                };
                psbt.outputs_mut()
                    .find(|o| o.script.is_p2tr() && o.script == tap_out_script)
                    .map(|o| o.set_tapret_host());
                // TODO: Add descriptor id to the tapret host data
                psbt.sort_outputs_by(|output| !output.is_tapret_host())
                    .expect("PSBT must be modifiable at this stage");
            }
            CloseMethod::OpretFirst => {
                psbt.set_opret_host();
                psbt.sort_outputs_by(|output| !output.is_opret_host())
                    .expect("PSBT must be modifiable at this stage");
            }
        }

        if let Some(ref change_script) = change_script {
            for output in psbt.outputs() {
                if output.script == *change_script {
                    meta.change_vout = Some(output.vout());
                    break;
                }
            }
        }

        let beneficiary_vout = match invoice.beneficiary.into_inner() {
            Beneficiary::WitnessVout(pay2vout, _) => {
                let s = script_buf_to_script_pubkey((*pay2vout).to_script());
                let vout = psbt
                    .outputs()
                    .find(|output| output.script == s)
                    .map(BpOutput::vout)
                    .expect("PSBT without beneficiary address");
                debug_assert_ne!(Some(vout), meta.change_vout);
                Some(vout)
            }
            Beneficiary::BlindedSeal(_) => None,
        };

        let mut meta: PsbtMeta = meta.into();
        meta.beneficiary_vout = beneficiary_vout.map(|v| v.into_u32());

        Ok((psbt, meta))
    }
}
