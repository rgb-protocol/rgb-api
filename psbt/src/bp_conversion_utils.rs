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

use amplify::ByteArray;
use bpstd::{
    ConsensusDecode, ConsensusEncode, IdxBase, InternalPk, NormalIndex, ScriptPubkey,
    Terminal as BpTerminal, Tx, Txid as BpTxid,
};
use rgbstd::bitcoin::hashes::{sha256d, Hash};
use rgbstd::bitcoin::key::UntweakedPublicKey;
use rgbstd::bitcoin::{consensus, Address, KnownHrp, Network};
use rgbstd::invoice::AddressPayload;
use rgbstd::Outpoint;

use super::*;

impl From<BpTerminal> for Terminal {
    fn from(value: BpTerminal) -> Self {
        Self::new(value.keychain.into_inner(), value.index.index())
    }
}

impl From<Terminal> for BpTerminal {
    fn from(value: Terminal) -> Self {
        Self::new(value.keychain, NormalIndex::normal(value.index as u16))
    }
}

pub fn address_bp_to_bitcoin(address: bpstd::Address) -> Address {
    Address::from_str(&address.to_string())
        .unwrap()
        .assume_checked()
}

pub fn address_bitcoin_to_bp(address: Address) -> bpstd::Address {
    bpstd::Address::from_str(&address.to_string()).unwrap()
}

pub fn address_network_bitcoin_to_bp(address_network: KnownHrp) -> bpstd::AddressNetwork {
    match address_network {
        KnownHrp::Mainnet => bpstd::AddressNetwork::Mainnet,
        KnownHrp::Testnets => bpstd::AddressNetwork::Testnet,
        KnownHrp::Regtest => bpstd::AddressNetwork::Regtest,
        _ => unimplemented!(),
    }
}

pub fn address_payload_bp_from_script_pubkey(script: &ScriptPubkey) -> bpstd::AddressPayload {
    bpstd::AddressPayload::from_script(script).unwrap()
}

pub fn address_payload_bitcoin_from_script_pubkey(script_pubkey: &ScriptPubkey) -> AddressPayload {
    AddressPayload::from_script(&script_pubkey_to_script_buf((*script_pubkey).clone())).unwrap()
}

pub fn network_bp_to_bitcoin(network: bpstd::Network) -> Network {
    match network {
        bpstd::Network::Mainnet => Network::Bitcoin,
        bpstd::Network::Signet => Network::Signet,
        bpstd::Network::Testnet3 => Network::Testnet,
        bpstd::Network::Testnet4 => Network::Testnet4,
        bpstd::Network::Regtest => Network::Regtest,
    }
}

pub fn outpoint_bp_to_bitcoin(outpoint: bpstd::Outpoint) -> Outpoint {
    Outpoint::new(txid_bp_to_bitcoin(outpoint.txid), outpoint.vout.to_u32())
}

pub fn outpoint_bitcoin_to_bp(outpoint: Outpoint) -> bpstd::Outpoint {
    bpstd::Outpoint::new(txid_bitcoin_to_bp(outpoint.txid), bpstd::Vout::from_u32(outpoint.vout))
}

pub fn script_buf_to_script_pubkey(script_buf: ScriptBuf) -> ScriptPubkey {
    ScriptPubkey::from_unsafe(script_buf.into_bytes())
}

pub fn script_pubkey_to_script_buf(script_pubkey: ScriptPubkey) -> ScriptBuf {
    ScriptBuf::from((*script_pubkey).clone().into_vec())
}

pub fn tx_bp_to_bitcoin(tx: Tx) -> Transaction {
    consensus::deserialize(&tx.consensus_serialize()).unwrap()
}

pub fn tx_bitcoin_to_bp(tx: Transaction) -> Tx {
    Tx::consensus_deserialize(consensus::serialize(&tx)).unwrap()
}

pub fn txid_bp_to_bitcoin(txid: BpTxid) -> Txid {
    Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(&txid.to_byte_array()))
}

pub fn txid_bitcoin_to_bp(txid: Txid) -> bpstd::Txid {
    bpstd::Txid::from_slice(txid.to_raw_hash().as_byte_array()).unwrap()
}

pub fn internal_pk_to_untweakedpublickey(internal_pk: InternalPk) -> UntweakedPublicKey {
    UntweakedPublicKey::from_slice(&internal_pk.to_xonly_pk().serialize()).unwrap()
}

pub fn untweakedpublickey_to_internal_pk(key: UntweakedPublicKey) -> InternalPk {
    InternalPk::from_byte_array(key.serialize()).unwrap()
}
