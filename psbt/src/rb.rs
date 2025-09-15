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

use rgbstd::bitcoin::key::Secp256k1;
use rgbstd::bitcoin::psbt::raw::ProprietaryKey;
use rgbstd::bitcoin::psbt::{raw, Output};
use rgbstd::bitcoin::taproot::{LeafVersion, TaprootBuilder};
use rgbstd::bitcoin::{Amount, Psbt, TxOut};

use super::*;

const PSBT_GLOBAL_TX_MODIFIABLE: u8 = 0x06;
const OUTPUTS_MODIFIABLE: u8 = 1 << 1;

fn tx_modifiable_key() -> raw::Key {
    raw::Key {
        type_value: PSBT_GLOBAL_TX_MODIFIABLE,
        key: Vec::new(),
    }
}

fn get_tx_modifiable_flags(psbt: &Psbt) -> u8 {
    psbt.unknown
        .get(&tx_modifiable_key())
        .and_then(|v| v.first().copied())
        .unwrap_or(0)
}

fn set_tx_modifiable_flags(psbt: &mut Psbt, flags: u8) {
    psbt.unknown.insert(tx_modifiable_key(), vec![flags]);
}

impl RgbPropKeyExt for ProprietaryKey {
    fn mpc_message(protocol_id: ProtocolId) -> Self {
        Self {
            prefix: PSBT_MPC_PREFIX.to_vec(),
            subtype: PSBT_OUT_MPC_MESSAGE,
            key: protocol_id.to_vec(),
        }
    }

    fn mpc_entropy() -> Self {
        Self {
            prefix: PSBT_MPC_PREFIX.to_vec(),
            subtype: PSBT_OUT_MPC_ENTROPY,
            key: empty!(),
        }
    }

    fn mpc_min_tree_depth() -> Self {
        Self {
            prefix: PSBT_MPC_PREFIX.to_vec(),
            subtype: PSBT_OUT_MPC_MIN_TREE_DEPTH,
            key: empty!(),
        }
    }

    fn mpc_commitment() -> Self {
        Self {
            prefix: PSBT_MPC_PREFIX.to_vec(),
            subtype: PSBT_OUT_MPC_COMMITMENT,
            key: empty!(),
        }
    }

    fn mpc_proof() -> Self {
        Self {
            prefix: PSBT_MPC_PREFIX.to_vec(),
            subtype: PSBT_OUT_MPC_PROOF,
            key: empty!(),
        }
    }

    fn opret_host() -> Self {
        Self {
            prefix: PSBT_OPRET_PREFIX.to_vec(),
            subtype: PSBT_OUT_OPRET_HOST,
            key: none!(),
        }
    }

    fn tapret_host() -> Self {
        Self {
            prefix: PSBT_TAPRET_PREFIX.to_vec(),
            subtype: PSBT_OUT_TAPRET_HOST,
            key: none!(),
        }
    }

    fn opret_commitment() -> Self {
        Self {
            prefix: PSBT_OPRET_PREFIX.to_vec(),
            subtype: PSBT_OUT_OPRET_COMMITMENT,
            key: none!(),
        }
    }

    fn tapret_commitment() -> Self {
        Self {
            prefix: PSBT_TAPRET_PREFIX.to_vec(),
            subtype: PSBT_OUT_TAPRET_COMMITMENT,
            key: none!(),
        }
    }

    fn tapret_proof() -> Self {
        Self {
            prefix: PSBT_TAPRET_PREFIX.to_vec(),
            subtype: PSBT_OUT_TAPRET_PROOF,
            key: none!(),
        }
    }

    fn rgb_transition(opid: OpId) -> Self {
        Self {
            prefix: PSBT_RGB_PREFIX.to_vec(),
            subtype: PSBT_GLOBAL_RGB_TRANSITION,
            key: opid.to_vec(),
        }
    }

    fn rgb_close_method() -> Self {
        Self {
            prefix: PSBT_RGB_PREFIX.to_vec(),
            subtype: PSBT_GLOBAL_RGB_CLOSE_METHOD,
            key: none!(),
        }
    }

    fn rgb_consumed_by(contract_id: ContractId) -> Self {
        Self {
            prefix: PSBT_RGB_PREFIX.to_vec(),
            subtype: PSBT_GLOBAL_RGB_CONSUMED_BY,
            key: contract_id.to_vec(),
        }
    }

    fn rgb_tapret_host_on_change() -> Self {
        Self {
            prefix: PSBT_RGB_PREFIX.to_vec(),
            subtype: PSBT_GLOBAL_RGB_TAP_HOST_CHANGE,
            key: none!(),
        }
    }
}

impl RgbOutExt<ProprietaryKey> for Output {
    fn get_internal_pk(&self) -> Option<UntweakedPublicKey> { self.tap_internal_key }

    fn is_tap_tree_empty(&self) -> bool { self.tap_tree.is_none() }

    fn set_tap_tree(&mut self, script_commitment: &ScriptBuf) {
        let builder = TaprootBuilder::new()
            .add_leaf_with_ver(0, script_commitment.clone(), LeafVersion::TapScript)
            .expect("one leaf cannot be unordered");
        let tap_tree = builder
            .try_into_taptree()
            .expect("tree with one leaf is always complete");
        self.tap_tree = Some(tap_tree);
    }

    fn bip32_derivation_terminals(&self) -> Vec<Terminal> {
        self.bip32_derivation
            .values()
            .filter_map(|(_, d)| Terminal::from_derivation_path(d))
            .collect()
    }

    fn tap_bip32_derivation_terminals(&self) -> Vec<Terminal> {
        self.tap_key_origins
            .values()
            .filter_map(|(_, (_, d))| Terminal::from_derivation_path(d))
            .collect()
    }

    fn proprietary_mpc_messages<'a>(&'a self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + 'a {
        self.proprietary
            .iter()
            .filter(|(key, _)| key.prefix == PSBT_MPC_PREFIX && key.subtype == PSBT_OUT_MPC_MESSAGE)
            .map(|(key, val)| (key.key.as_slice(), val.as_slice()))
    }

    fn proprietary_insert(&mut self, key: ProprietaryKey, value: Vec<u8>) {
        self.proprietary.insert(key, value);
    }

    fn proprietary_contains_key(&self, key: &ProprietaryKey) -> bool {
        self.proprietary.contains_key(key)
    }

    fn proprietary_get_value(&self, key: &ProprietaryKey) -> Option<&[u8]> {
        self.proprietary.get(key).map(|v| v.as_slice())
    }

    fn proprietary_remove(&mut self, key: &ProprietaryKey) { self.proprietary.remove(key); }
}

impl RgbPsbtExt<ProprietaryKey, Output> for Psbt {
    fn get_txid(&self) -> rgbstd::Txid { self.unsigned_tx.compute_txid() }

    fn modifiable_outputs(&self) -> bool {
        (get_tx_modifiable_flags(self) & OUTPUTS_MODIFIABLE) != 0
    }

    fn set_as_unmodifiable(&mut self) {
        let mut flags = get_tx_modifiable_flags(self);
        flags &= !OUTPUTS_MODIFIABLE;
        set_tx_modifiable_flags(self, flags);
    }

    fn unsigned_tx(&self) -> Transaction { self.unsigned_tx.clone() }

    fn set_opret_host(&mut self) -> bool {
        let idx = if let Some((idx, _out)) = self
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find(|(_i, o)| o.script_pubkey.is_op_return())
        {
            idx
        } else {
            let opreturn_output = TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return([]),
            };
            self.unsigned_tx.output.insert(0, opreturn_output);
            self.outputs.insert(0, Output::default());
            0
        };
        self.outputs[idx].set_opret_host()
    }

    fn dbc_output<D: DbcPsbtProof>(&self) -> Option<&Output> {
        let (idx, _) = self
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find(|(_i, output)| {
                (output.script_pubkey.is_p2tr() && D::METHOD == CloseMethod::TapretFirst)
                    || (output.script_pubkey.is_op_return() && D::METHOD == CloseMethod::OpretFirst)
            })?;
        Some(&self.outputs[idx])
    }

    fn dbc_output_mut<D: DbcPsbtProof>(&mut self) -> Option<(usize, &mut Output)> {
        let (idx, _) = self
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find(|(_i, output)| {
                (output.script_pubkey.is_p2tr() && D::METHOD == CloseMethod::TapretFirst)
                    || (output.script_pubkey.is_op_return() && D::METHOD == CloseMethod::OpretFirst)
            })?;
        Some((idx, self.outputs.get_mut(idx).unwrap()))
    }

    fn set_opret_commitment(&mut self, idx: usize) {
        let commitment = self.outputs[idx]
            .proprietary_get(&ProprietaryKey::opret_commitment())
            .unwrap();
        let commitment: [u8; 32] = commitment.try_into().unwrap();
        let script = ScriptBuf::new_op_return(commitment);
        self.unsigned_tx.output[idx].script_pubkey = script;
    }

    fn set_tapret_commitment(&mut self, idx: usize) {
        let output = &self.outputs[idx];
        let internal_pk = output.tap_internal_key.unwrap();
        let tap_tree = output.tap_tree.as_ref().unwrap();
        let merkle_root = tap_tree.root_hash();
        let script = ScriptBuf::new_p2tr(&Secp256k1::new(), internal_pk, Some(merkle_root));
        self.unsigned_tx.output[idx].script_pubkey = script;
    }

    fn proprietary_rgb_contract_consumer_keys<'a>(&'a self) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.proprietary
            .keys()
            .filter(|prop_key| {
                prop_key.prefix == PSBT_RGB_PREFIX
                    && prop_key.subtype == PSBT_GLOBAL_RGB_CONSUMED_BY
            })
            .map(|prop_key| prop_key.key.as_slice())
    }

    fn outputs_iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut Output>
    where Output: 'a {
        self.outputs.iter_mut()
    }

    fn proprietary_insert(&mut self, key: ProprietaryKey, value: Vec<u8>) {
        self.proprietary.insert(key, value);
    }

    fn proprietary_contains_key(&self, key: &ProprietaryKey) -> bool {
        self.proprietary.contains_key(key)
    }

    fn proprietary_get_value(&self, key: &ProprietaryKey) -> Option<&[u8]> {
        self.proprietary.get(key).map(|v| v.as_slice())
    }
}
