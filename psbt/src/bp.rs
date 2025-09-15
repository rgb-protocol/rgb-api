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

use bpstd::psbt::{KeyMap, Output, PropKey};
use bpstd::{ByteStr, Psbt, Sats, ScriptPubkey, TapScript, TapTree, Tx};

use super::*;
use crate::bp_conversion_utils::{
    internal_pk_to_untweakedpublickey, tx_bp_to_bitcoin, txid_bp_to_bitcoin,
};

impl RgbPropKeyExt for PropKey {
    fn mpc_message(protocol_id: ProtocolId) -> Self {
        Self {
            identifier: PSBT_MPC_PREFIX_STR.to_owned(),
            subtype: PSBT_OUT_MPC_MESSAGE as u64,
            data: ByteStr::from(protocol_id.to_vec()),
        }
    }

    fn mpc_entropy() -> Self {
        Self {
            identifier: PSBT_MPC_PREFIX_STR.to_owned(),
            subtype: PSBT_OUT_MPC_ENTROPY as u64,
            data: empty!(),
        }
    }

    fn mpc_min_tree_depth() -> Self {
        Self {
            identifier: PSBT_MPC_PREFIX_STR.to_owned(),
            subtype: PSBT_OUT_MPC_MIN_TREE_DEPTH as u64,
            data: empty!(),
        }
    }

    fn mpc_commitment() -> Self {
        Self {
            identifier: PSBT_MPC_PREFIX_STR.to_owned(),
            subtype: PSBT_OUT_MPC_COMMITMENT as u64,
            data: empty!(),
        }
    }

    fn mpc_proof() -> Self {
        Self {
            identifier: PSBT_MPC_PREFIX_STR.to_owned(),
            subtype: PSBT_OUT_MPC_PROOF as u64,
            data: empty!(),
        }
    }

    fn opret_host() -> Self {
        Self {
            identifier: PSBT_OPRET_PREFIX_STR.to_owned(),
            subtype: PSBT_OUT_OPRET_HOST as u64,
            data: none!(),
        }
    }

    fn tapret_host() -> Self {
        Self {
            identifier: PSBT_TAPRET_PREFIX_STR.to_owned(),
            subtype: PSBT_OUT_TAPRET_HOST as u64,
            data: none!(),
        }
    }

    fn opret_commitment() -> Self {
        Self {
            identifier: PSBT_OPRET_PREFIX_STR.to_owned(),
            subtype: PSBT_OUT_OPRET_COMMITMENT as u64,
            data: none!(),
        }
    }

    fn tapret_commitment() -> Self {
        Self {
            identifier: PSBT_TAPRET_PREFIX_STR.to_owned(),
            subtype: PSBT_OUT_TAPRET_COMMITMENT as u64,
            data: none!(),
        }
    }

    fn tapret_proof() -> Self {
        Self {
            identifier: PSBT_TAPRET_PREFIX_STR.to_owned(),
            subtype: PSBT_OUT_TAPRET_PROOF as u64,
            data: none!(),
        }
    }

    fn rgb_transition(opid: OpId) -> Self {
        Self {
            identifier: PSBT_RGB_PREFIX_STR.to_owned(),
            subtype: PSBT_GLOBAL_RGB_TRANSITION as u64,
            data: opid.to_vec().into(),
        }
    }

    fn rgb_close_method() -> Self {
        Self {
            identifier: PSBT_RGB_PREFIX_STR.to_owned(),
            subtype: PSBT_GLOBAL_RGB_CLOSE_METHOD as u64,
            data: none!(),
        }
    }

    fn rgb_consumed_by(contract_id: ContractId) -> Self {
        Self {
            identifier: PSBT_RGB_PREFIX_STR.to_owned(),
            subtype: PSBT_GLOBAL_RGB_CONSUMED_BY as u64,
            data: contract_id.to_vec().into(),
        }
    }

    fn rgb_tapret_host_on_change() -> Self {
        Self {
            identifier: PSBT_RGB_PREFIX_STR.to_owned(),
            subtype: PSBT_GLOBAL_RGB_TAP_HOST_CHANGE as u64,
            data: none!(),
        }
    }
}

impl RgbOutExt<PropKey> for Output {
    fn get_internal_pk(&self) -> Option<UntweakedPublicKey> {
        self.tap_internal_key.map(internal_pk_to_untweakedpublickey)
    }

    fn is_tap_tree_empty(&self) -> bool { self.tap_tree.is_none() }

    fn set_tap_tree(&mut self, script_commitment: &ScriptBuf) {
        let tap_tree =
            TapTree::with_single_leaf(TapScript::from_unsafe(script_commitment.to_bytes()));
        self.tap_tree = Some(tap_tree);
    }

    fn bip32_derivation_terminals(&self) -> Vec<Terminal> {
        self.bip32_derivation
            .values()
            .filter_map(|o| o.derivation().terminal().map(Terminal::from))
            .collect()
    }

    fn tap_bip32_derivation_terminals(&self) -> Vec<Terminal> {
        self.tap_bip32_derivation
            .values()
            .filter_map(|d| d.origin.derivation().terminal().map(Terminal::from))
            .collect()
    }

    fn proprietary_mpc_messages<'a>(&'a self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + 'a {
        self.proprietary
            .iter()
            .filter(|(key, _)| {
                key.identifier == PSBT_MPC_PREFIX_STR && key.subtype == PSBT_OUT_MPC_MESSAGE as u64
            })
            .map(|(key, val)| (key.data.as_slice(), val.as_slice()))
    }

    fn proprietary_insert(&mut self, key: PropKey, value: Vec<u8>) {
        self.proprietary.insert(key, value.into());
    }

    fn proprietary_contains_key(&self, key: &PropKey) -> bool { self.has_proprietary(key) }

    fn proprietary_get_value(&self, key: &PropKey) -> Option<&[u8]> {
        self.proprietary(key).map(|v| v.as_slice())
    }

    fn proprietary_remove(&mut self, key: &PropKey) { self.remove_proprietary(key); }
}

impl RgbPsbtExt<PropKey, Output> for Psbt {
    fn get_txid(&self) -> Txid { txid_bp_to_bitcoin(self.txid()) }

    fn modifiable_outputs(&self) -> bool { self.are_outputs_modifiable() }

    fn set_as_unmodifiable(&mut self) { self.complete_construction(); }

    fn unsigned_tx(&self) -> Transaction {
        let tx: Tx = self.to_unsigned_tx().into();
        tx_bp_to_bitcoin(tx)
    }

    fn set_opret_host(&mut self) -> bool {
        let mut out = self.outputs_mut().find(|o| o.script.is_op_return());
        if out.is_none() {
            out = Some(self.construct_output_expect(ScriptPubkey::op_return(&[]), Sats::ZERO));
        }
        out.unwrap().set_opret_host()
    }

    fn dbc_output<D: DbcPsbtProof>(&self) -> Option<&Output> {
        self.outputs().find(|output| {
            (output.script.is_p2tr() && D::METHOD == CloseMethod::TapretFirst)
                || (output.script.is_op_return() && D::METHOD == CloseMethod::OpretFirst)
        })
    }

    fn dbc_output_mut<D: DbcPsbtProof>(&mut self) -> Option<(usize, &mut Output)> {
        self.outputs_mut().enumerate().find(|(_i, output)| {
            (output.script.is_p2tr() && D::METHOD == CloseMethod::TapretFirst)
                || (output.script.is_op_return() && D::METHOD == CloseMethod::OpretFirst)
        })
    }

    fn set_opret_commitment(&mut self, idx: usize) {
        let commitment = self
            .output(idx)
            .unwrap()
            .proprietary_get(&PropKey::opret_commitment())
            .unwrap();
        let script = ScriptPubkey::op_return(commitment);
        self.output_mut(idx).unwrap().script = script;
    }

    fn set_tapret_commitment(&mut self, idx: usize) {
        let output = self.output(idx).unwrap();
        let internal_pk = output.tap_internal_key.unwrap();
        let tap_tree = output.tap_tree.as_ref().unwrap();
        let merkle_root = tap_tree.merkle_root();
        let script = ScriptPubkey::p2tr(internal_pk, Some(merkle_root));
        self.output_mut(idx).unwrap().script = script;
    }

    fn proprietary_rgb_contract_consumer_keys<'a>(&'a self) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.proprietary
            .keys()
            .filter(|prop_key| {
                prop_key.identifier == PSBT_RGB_PREFIX_STR
                    && prop_key.subtype == PSBT_GLOBAL_RGB_CONSUMED_BY as u64
            })
            .map(|prop_key| prop_key.data.as_slice())
    }

    fn outputs_iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut Output>
    where Output: 'a {
        self.outputs_mut()
    }

    fn proprietary_insert(&mut self, key: PropKey, value: Vec<u8>) {
        self.proprietary.insert(key, value.into());
    }

    fn proprietary_contains_key(&self, key: &PropKey) -> bool { self.has_proprietary(key) }

    fn proprietary_get_value(&self, key: &PropKey) -> Option<&[u8]> {
        self.proprietary.get(key).map(|v| v.as_slice())
    }
}
