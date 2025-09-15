// RGB API library for smart contracts on Bitcoin & Lightning network
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2025 RGB-Tools developers. All rights reserved.
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

use bdk_wallet::bitcoin::psbt::raw::ProprietaryKey as BdkPropKey;
use bdk_wallet::bitcoin::psbt::{Output as BdkOutput, Psbt as BdkPsbt};
use bdk_wallet::bitcoin::{Amount, ScriptBuf};
use bdk_wallet::{PersistedWallet, TxOrdering};
use psrgbt::{RgbPsbtExt, Terminal};
use rgbstd::containers::Transfer;
use rgbstd::invoice::{Beneficiary, RgbInvoice};
use rgbstd::rgbcore::dbc::tapret::TapretCommitment;
use rgbstd::rgbcore::seals::txout::CloseMethod;
use rgbstd::{Outpoint, Txid};

use super::*;
use crate::pay::PsbtMeta;
use crate::{CompositionError, WalletError};

impl<D> WalletProvider for PersistedWallet<D> {
    type P = BdkPropKey;
    type O = BdkOutput;
    type Psbt = BdkPsbt;

    fn close_method(&self) -> CloseMethod {
        // until BDK supports Tapret tweaks
        CloseMethod::OpretFirst
    }

    fn is_unspent(&self, outpoint: Outpoint) -> bool {
        self.list_unspent().any(|utxo| utxo.outpoint == outpoint)
    }

    fn has_outpoint(&self, outpoint: Outpoint) -> bool {
        self.list_output().any(|output| output.outpoint == outpoint)
    }

    fn should_include_witness(&self, witness_id: Option<Txid>) -> bool {
        if let Some(witness_id) = witness_id {
            self.transactions().any(|tx| tx.tx_node.txid == witness_id)
        } else {
            false
        }
    }

    fn add_tapret_tweak(
        &mut self,
        _terminal: Terminal,
        _tweak: TapretCommitment,
    ) -> Result<(), Infallible> {
        panic!("BDK does not support Tapret tweaks")
    }

    fn try_add_tapret_tweak(
        &mut self,
        _transfer: Transfer,
        _txid: &Txid,
    ) -> Result<(), Box<WalletError>> {
        Err(Box::new(WalletError::Custom("BDK does not support Tapret tweaks".to_string())))
    }

    fn create_psbt(
        &mut self,
        invoice: &RgbInvoice,
        close_method: CloseMethod,
        prev_outpoints: impl IntoIterator<Item = Outpoint>,
        params: TransferParams,
    ) -> Result<(Self::Psbt, PsbtMeta), CompositionError> {
        if matches!(close_method, CloseMethod::TapretFirst) {
            return Err(CompositionError::UnsupportedCloseMethod(
                "BDK does not support Tapret commitment method".to_string(),
            ));
        }

        let mut tx_builder = self.build_tx();
        tx_builder
            .ordering(TxOrdering::Untouched)
            .add_data(&[0; 32]);

        for outpoint in prev_outpoints {
            tx_builder
                .add_utxo(outpoint)
                .map_err(|e| CompositionError::Unexpected(e.to_string()))?;
        }

        let (_, beneficiary_script) = match invoice.beneficiary.into_inner() {
            Beneficiary::BlindedSeal(_) => (None, None),
            Beneficiary::WitnessVout(pay2vout, _) => {
                let script = ScriptBuf::from_bytes(pay2vout.to_script().to_bytes());
                tx_builder.add_recipient(script.clone(), Amount::from_sat(params.min_amount));
                (Some(0u32), Some(script))
            }
        };

        tx_builder.fee_absolute(Amount::from_sat(params.tx.fee_sats));

        let mut psbt = tx_builder
            .finish()
            .map_err(|e| CompositionError::Unexpected(e.to_string()))?;

        let beneficiary_vout = if let Some(script) = beneficiary_script.clone() {
            psbt.unsigned_tx
                .output
                .iter()
                .position(|o| o.script_pubkey == script)
                .map(|i| i as u32)
        } else {
            None
        };

        let change_vout = psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find(|(idx, output)| {
                self.is_mine(output.script_pubkey.clone())
                    && (beneficiary_vout != Some(*idx as u32))
            })
            .map(|(idx, _)| idx as u32);

        psbt.set_opret_host();

        let meta = PsbtMeta {
            beneficiary_vout,
            change_vout,
        };

        Ok((psbt, meta))
    }
}
