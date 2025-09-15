// Partially signed bitcoin transaction RGB extensions
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2020-2023 by
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

#[macro_use]
extern crate amplify;

#[cfg(feature = "bp")]
mod bp;
#[cfg(feature = "bp")]
pub mod bp_conversion_utils;
mod rb;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;

use amplify::confinement::{Confined, NonEmptyOrdMap, SmallVec, U16, U24, U32};
use amplify::num::u5;
use amplify::{confinement, FromSliceError, Wrapper};
use rgbstd::bitcoin::bip32::DerivationPath;
use rgbstd::bitcoin::key::UntweakedPublicKey;
use rgbstd::bitcoin::{ScriptBuf, Transaction};
use rgbstd::containers::{Batch, Fascia, PubWitness, SealWitness};
use rgbstd::opret::OpretProof;
use rgbstd::rgbcore::commit_verify::mpc::{
    self, Commitment, Message, ProtocolId, MPC_MINIMAL_DEPTH,
};
use rgbstd::rgbcore::commit_verify::{CommitId, TryCommitVerify};
use rgbstd::tapret::{TapretCommitment, TapretPathProof, TapretProof};
use rgbstd::txout::CloseMethod;
use rgbstd::{
    AssignmentType, ContractId, KnownTransition, MergeReveal, MergeRevealError, OpId, Operation,
    Opout, Proof, Transition, TransitionBundle, Txid,
};
use strict_encoding::{DeserializeError, StrictDeserialize, StrictSerialize};

// TODO: Instead of storing whole RGB contract in PSBT create a shortened
//       contract version which skips all info not important for hardware
//       signers
// /// Proprietary key subtype for storing RGB contract consignment in
// /// global map.
// pub const PSBT_GLOBAL_RGB_CONTRACT: u8 = 0x00;

/// PSBT proprietary key prefix used for MPC.
pub const PSBT_MPC_PREFIX: [u8; 3] = [77, 80, 67];
pub const PSBT_MPC_PREFIX_STR: &str = "MPC";
/// Proprietary key subtype for storing MPC single commitment message under
/// some protocol in global map.
pub const PSBT_OUT_MPC_MESSAGE: u8 = 0x00;
/// Proprietary key subtype for storing MPC entropy constant.
pub const PSBT_OUT_MPC_ENTROPY: u8 = 0x01;
/// Proprietary key subtype for storing MPC requirement for a minimal tree
/// size.
pub const PSBT_OUT_MPC_MIN_TREE_DEPTH: u8 = 0x04;
/// The final multi-protocol commitment value.
pub const PSBT_OUT_MPC_COMMITMENT: u8 = 0x10;
/// The multi-protocol commitment proof.
pub const PSBT_OUT_MPC_PROOF: u8 = 0x11;

/// PSBT proprietary key prefix used for opret commitment.
pub const PSBT_OPRET_PREFIX: [u8; 5] = [79, 80, 82, 69, 84];
pub const PSBT_OPRET_PREFIX_STR: &str = "OPRET";
/// Proprietary key subtype marking PSBT outputs which may host opret
/// commitment.
pub const PSBT_OUT_OPRET_HOST: u8 = 0x00;
/// Proprietary key subtype holding 32-byte commitment which will be put into
/// opret data.
pub const PSBT_OUT_OPRET_COMMITMENT: u8 = 0x01;

/// PSBT proprietary key prefix used for tapreturn commitment.
pub const PSBT_TAPRET_PREFIX: [u8; 5] = [84, 65, 82, 69, 84];
pub const PSBT_TAPRET_PREFIX_STR: &str = "TAPRET";
/// Proprietary key subtype marking PSBT outputs which may host tapreturn
/// commitment.
pub const PSBT_OUT_TAPRET_HOST: u8 = 0x00;
/// Proprietary key subtype holding 32-byte commitment which will be put into
/// tapret tweak.
pub const PSBT_OUT_TAPRET_COMMITMENT: u8 = 0x01;
/// Proprietary key subtype holding merkle branch path to tapreturn tweak inside
/// the taptree structure.
pub const PSBT_OUT_TAPRET_PROOF: u8 = 0x02;

/// PSBT proprietary key prefix used for RGB.
pub const PSBT_RGB_PREFIX: [u8; 3] = [82, 71, 66];
pub const PSBT_RGB_PREFIX_STR: &str = "RGB";
/// Proprietary key subtype for storing RGB state transition in global map.
pub const PSBT_GLOBAL_RGB_TRANSITION: u8 = 0x01;
/// Proprietary key subtype for storing information on which close method
/// should be used.
pub const PSBT_GLOBAL_RGB_CLOSE_METHOD: u8 = 0x02;
/// Proprietary key subtype to signal that tapret host has been put on change.
pub const PSBT_GLOBAL_RGB_TAP_HOST_CHANGE: u8 = 0x03;
/// Proprietary key subtype for storing RGB input allocation and ID of the
/// transition spending it.
pub const PSBT_GLOBAL_RGB_CONSUMED_BY: u8 = 0x04;

/// Errors processing MPC-related proprietary PSBT keys and their values.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum MpcPsbtError {
    /// the key contains invalid value.
    #[from(FromSliceError)]
    InvalidKeyValue,

    /// message map produced from PSBT inputs exceeds maximum size bounds.
    #[from]
    MessageMapTooLarge(confinement::Error),

    /// key is already present.
    KeyAlreadyPresent,

    /// output already contains commitment; there must be a single commitment
    /// per output.
    OutputAlreadyHasCommitment,

    #[from]
    #[display(inner)]
    Mpc(mpc::Error),

    /// multi-protocol commitment is already finalized.
    Finalized,
}

/// Errors processing opret-related proprietary PSBT keys and their values.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum OpretKeyError {
    /// output already contains commitment; there must be a single commitment
    /// per output.
    OutputAlreadyHasCommitment,

    /// the output can't host a commitment since it does not contain OP_RETURN
    /// script
    NonOpReturnOutput,

    /// the output is not marked to host opret commitments. Please first set
    /// PSBT_OUT_OPRET_HOST flag.
    OpretProhibited,

    /// the output contains no valid opret commitment.
    NoCommitment,

    /// the value of opret commitment has invalid length.
    InvalidCommitment,

    /// the script format doesn't match requirements for opret commitment.
    InvalidOpReturnScript,
}

/// Errors processing tapret-related proprietary PSBT keys and their values.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum TapretKeyError {
    /// output already contains commitment; there must be a single commitment
    /// per output.
    OutputAlreadyHasCommitment,

    /// the output is not marked to host tapret commitments. Please first set
    /// PSBT_OUT_TAPRET_HOST flag.
    TapretProhibited,

    /// the provided output is not a taproot output and can't host a tapret
    /// commitment.
    NotTaprootOutput,

    /// the output contains no valid tapret commitment.
    NoCommitment,

    /// the value of tapret commitment has invalid length.
    InvalidCommitment,

    /// use of taproot script descriptors is not yet supported.
    TapTreeNonEmpty,

    /// taproot output doesn't specify internal key.
    NoInternalKey,
}

/// Errors processing RGB-related proprietary PSBT keys and their values.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum RgbPsbtError {
    /// the opout is already signalled as spent by a different opid
    DoubleSpend,

    /// state transition {0} already present in PSBT is not related to the state
    /// transition {1} which has to be added to RGB
    UnrelatedTransitions(OpId, OpId, MergeRevealError),

    /// PSBT contains no contract information
    NoContracts,

    /// PSBT contains no contract consumers information
    NoContractConsumers,

    /// contract {0} listed in the PSBT has an invalid number of known transitions {1}.
    InvalidTransitionsNumber(ContractId, usize),

    /// inputs listed in the PSBT have an invalid number {0}.
    InvalidInputsNumber(usize),

    /// invalid contract id data.
    #[from(FromSliceError)]
    InvalidContractId,

    /// invalid opout and opids data: {0}.
    InvalidOpoutAndOpidsData(String),

    /// data inconsistency in bundle's known transitions
    KnownTransitionsInconsistency,

    /// PSBT doesn't provide information about close method.
    NoCloseMethod,

    /// PSBT provides invalid close method information.
    InvalidCloseMethod,

    /// PSBT doesn't specify an output which can host {0} commitment.
    NoHostOutput(CloseMethod),

    /// PSBT contains too many contracts.
    TooManyContracts,

    /// PSBT contains too many state transitions for a bundle.
    #[from(confinement::Error)]
    TooManyTransitionsInBundle,

    /// the transition with opid {0} is too big.
    TransitionTooBig(OpId),

    /// state transition data in PSBT are invalid. Details: {0}
    #[from]
    InvalidTransition(DeserializeError),

    /// MPC PSBT error
    #[from]
    #[display(inner)]
    Mpc(MpcPsbtError),
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum EmbedError {
    #[from]
    Rgb(RgbPsbtError),
}

/// Errors processing DBC-related proprietary PSBT keys and their values.
#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum DbcPsbtError {
    /// the first output valid for a DBC commitment is not marked as a commitment host.
    NoHostOutput,

    /// the transactions contains no output valid for {0} DBC commitment.
    NoProperOutput(CloseMethod),

    /// DBC commitment is already present.
    AlreadyPresent,

    /// transaction outputs are marked as modifiable, thus deterministic bitcoin commitment can't
    /// be created.
    TxOutputsModifiable,

    /// MPC PSBT error
    #[from]
    #[display(inner)]
    Mpc(MpcPsbtError),

    /// Tapret key error
    #[from]
    #[display(inner)]
    Tapret(TapretKeyError),

    /// Opret key error
    #[from]
    #[display(inner)]
    Opret(OpretKeyError),
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(inner)]
pub enum CommitError {
    #[from]
    Rgb(RgbPsbtError),

    #[from]
    Dbc(DbcPsbtError),
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
#[display("&{keychain}/{index}")]
pub struct Terminal {
    pub keychain: u8,
    pub index: u32,
}

impl Terminal {
    pub fn new(keychain: u8, index: u32) -> Self { Self { keychain, index } }

    pub fn from_derivation_path(derivation_path: &DerivationPath) -> Option<Self> {
        let mut path = derivation_path.to_u32_vec();
        path.reverse();
        let index = path.pop()?;
        let keychain = u8::try_from(path.pop()?).ok()?;
        Some(Self::new(keychain, index))
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum TerminalParseError {
    /// terminal derivation path must start with keychain index prefixed with '&'.
    NoKeychain,

    /// keychain or index in terminal derivation path is not a number.
    #[from]
    InvalidTerminal(std::num::ParseIntError),

    /// derivation path '{0}' is not a terminal path - terminal path must contain exactly two
    /// components.
    InvalidComponents(String),
}

impl FromStr for Terminal {
    type Err = TerminalParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut iter = s.split('/');
        match (iter.next(), iter.next(), iter.next()) {
            (Some(keychain), Some(index), None) => {
                if !keychain.starts_with('&') {
                    return Err(TerminalParseError::NoKeychain);
                }
                Ok(Terminal::new(u8::from_str(keychain.trim_start_matches('&'))?, index.parse()?))
            }
            _ => Err(TerminalParseError::InvalidComponents(s.to_owned())),
        }
    }
}

#[cfg(feature = "serde")]
mod _serde {
    use serde_crate::de::Error;
    use serde_crate::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for Terminal {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            if serializer.is_human_readable() {
                self.to_string().serialize(serializer)
            } else {
                let tuple = (self.keychain, self.index);
                tuple.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for Terminal {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            if deserializer.is_human_readable() {
                let s = String::deserialize(deserializer)?;
                Self::from_str(&s).map_err(D::Error::custom)
            } else {
                let d = <(u8, u32)>::deserialize(deserializer)?;
                Ok(Self {
                    keychain: d.0,
                    index: d.1,
                })
            }
        }
    }
}

pub trait DbcPsbtProof: Proof {
    const METHOD: CloseMethod;
    fn dbc_commit<P: RgbPropKeyExt, O: RgbOutExt<P>>(
        psbt: &mut impl RgbPsbtExt<P, O>,
    ) -> Result<(mpc::MerkleBlock, Self), DbcPsbtError>;
}

impl DbcPsbtProof for OpretProof {
    const METHOD: CloseMethod = CloseMethod::OpretFirst;

    fn dbc_commit<P: RgbPropKeyExt, O: RgbOutExt<P>>(
        psbt: &mut impl RgbPsbtExt<P, O>,
    ) -> Result<(mpc::MerkleBlock, Self), DbcPsbtError> {
        let (idx, output) = psbt
            .dbc_output_mut::<Self>()
            .ok_or(DbcPsbtError::NoProperOutput(Self::METHOD))?;

        let (commitment, mpc_proof) = output.mpc_commit()?;
        output.opret_commit(commitment)?;

        psbt.set_opret_commitment(idx);

        Ok((mpc_proof, OpretProof::default()))
    }
}

impl DbcPsbtProof for TapretProof {
    const METHOD: CloseMethod = CloseMethod::TapretFirst;

    fn dbc_commit<P: RgbPropKeyExt, O: RgbOutExt<P>>(
        psbt: &mut impl RgbPsbtExt<P, O>,
    ) -> Result<(mpc::MerkleBlock, Self), DbcPsbtError> {
        let (idx, output) = psbt
            .dbc_output_mut::<Self>()
            .ok_or(DbcPsbtError::NoProperOutput(Self::METHOD))?;

        let (commitment, mpc_proof) = output.mpc_commit()?;
        let tapret_proof = output.tapret_commit(commitment)?;

        psbt.set_tapret_commitment(idx);

        Ok((mpc_proof, tapret_proof))
    }
}

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
pub struct OpoutAndOpids(BTreeMap<Opout, OpId>);

impl OpoutAndOpids {
    pub fn new(items: BTreeMap<Opout, OpId>) -> Self { Self(items) }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (opout, opid) in &self.0 {
            bytes.extend(opout.op.to_byte_array());
            bytes.extend(opout.ty.to_le_bytes());
            bytes.extend(opout.no.to_le_bytes());
            bytes.extend(opid.to_byte_array());
        }
        bytes
    }

    #[allow(clippy::result_large_err)]
    pub fn deserialize(bytes: &[u8]) -> Result<Self, RgbPsbtError> {
        let opid_size = std::mem::size_of::<OpId>();
        let assignment_type_size = std::mem::size_of::<u16>();
        let u16_size = std::mem::size_of::<u16>();
        let item_size = opid_size + assignment_type_size + u16_size + opid_size;
        let bytes_len = bytes.len();
        if bytes_len % item_size != 0 {
            return Err(RgbPsbtError::InvalidOpoutAndOpidsData(format!(
                "Input data length {bytes_len} is not a multiple of {item_size}"
            )));
        }
        let mut items = BTreeMap::new();
        for chunk in bytes.chunks_exact(item_size) {
            let mut cursor = 0;
            let op = OpId::copy_from_slice(&chunk[cursor..cursor + opid_size]).map_err(|e| {
                RgbPsbtError::InvalidOpoutAndOpidsData(format!(
                    "Error deserializing Opout.op: {e:?}",
                ))
            })?;
            cursor += opid_size;
            let ty_bytes = &chunk[cursor..cursor + assignment_type_size];
            let ty_u16 = u16::from_le_bytes([ty_bytes[0], ty_bytes[1]]);
            let ty = AssignmentType::with(ty_u16);
            cursor += assignment_type_size;
            let no_bytes = &chunk[cursor..cursor + u16_size];
            let no = u16::from_le_bytes([no_bytes[0], no_bytes[1]]);
            cursor += u16_size;
            let opid = OpId::copy_from_slice(&chunk[cursor..cursor + opid_size]).map_err(|e| {
                RgbPsbtError::InvalidOpoutAndOpidsData(format!(
                    "Error deserializing consuming OpId: {e:?}"
                ))
            })?;
            let opout = Opout::new(op, ty, no);
            items.insert(opout, opid);
        }
        Ok(OpoutAndOpids::new(items))
    }
}

#[allow(clippy::result_large_err)]
fn insert_transitions_sorted(
    transitions: &HashMap<OpId, Transition>,
    known_transitions: &mut SmallVec<KnownTransition>,
) -> Result<(), RgbPsbtError> {
    #[allow(clippy::result_large_err)]
    fn visit_and_insert(
        opid: OpId,
        transitions: &HashMap<OpId, Transition>,
        known_transitions: &mut SmallVec<KnownTransition>,
        visited: &mut HashSet<OpId>,
        visiting: &mut HashSet<OpId>,
    ) -> Result<(), RgbPsbtError> {
        if visited.contains(&opid) {
            return Ok(());
        }
        if visiting.contains(&opid) {
            return Err(RgbPsbtError::KnownTransitionsInconsistency);
        }
        if let Some(transition) = transitions.get(&opid) {
            visiting.insert(opid);
            for input in transition.inputs() {
                if transitions.contains_key(&input.op) {
                    visit_and_insert(input.op, transitions, known_transitions, visited, visiting)?;
                }
            }
            visiting.remove(&opid);
            visited.insert(opid);
            known_transitions
                .push(KnownTransition {
                    opid,
                    transition: transition.clone(),
                })
                .map_err(|_| {
                    RgbPsbtError::InvalidTransitionsNumber(
                        transition.contract_id,
                        transitions.len(),
                    )
                })?;
        }
        Ok(())
    }

    let mut visited = HashSet::new();
    let mut visiting = HashSet::new();
    for &opid in transitions.keys() {
        visit_and_insert(opid, transitions, known_transitions, &mut visited, &mut visiting)?;
    }
    Ok(())
}

/// Extension trait for static functions returning RGB-related proprietary keys.
pub trait RgbPropKeyExt {
    /// Constructs [`PSBT_OUT_MPC_MESSAGE`] proprietary key.
    fn mpc_message(protocol_id: ProtocolId) -> Self;
    /// Constructs [`PSBT_OUT_MPC_ENTROPY`] proprietary key.
    fn mpc_entropy() -> Self;
    /// Constructs [`PSBT_OUT_MPC_MIN_TREE_DEPTH`] proprietary key.
    fn mpc_min_tree_depth() -> Self;
    /// Constructs [`PSBT_OUT_MPC_COMMITMENT`] proprietary key.
    fn mpc_commitment() -> Self;
    /// Constructs [`PSBT_OUT_MPC_PROOF`] proprietary key.
    fn mpc_proof() -> Self;
    /// Constructs [`PSBT_OUT_OPRET_HOST`] proprietary key.
    fn opret_host() -> Self;
    /// Constructs [`PSBT_OUT_TAPRET_HOST`] proprietary key.
    fn tapret_host() -> Self;
    /// Constructs [`PSBT_OUT_OPRET_COMMITMENT`] proprietary key.
    fn opret_commitment() -> Self;
    /// Constructs [`PSBT_OUT_TAPRET_COMMITMENT`] proprietary key.
    fn tapret_commitment() -> Self;
    /// Constructs [`PSBT_OUT_TAPRET_PROOF`] proprietary key.
    fn tapret_proof() -> Self;
    /// Constructs [`PSBT_GLOBAL_RGB_TRANSITION`] proprietary key.
    fn rgb_transition(opid: OpId) -> Self;
    /// Constructs [`PSBT_GLOBAL_RGB_CLOSE_METHOD`] proprietary key.
    fn rgb_close_method() -> Self;
    /// Constructs [`PSBT_GLOBAL_RGB_CONSUMED_BY`] proprietary key.
    fn rgb_consumed_by(contract_id: ContractId) -> Self;
    /// Constructs [`PSBT_GLOBAL_RGB_TAP_HOST_CHANGE`] proprietary key.
    fn rgb_tapret_host_on_change() -> Self;
}

pub trait RgbOutExt<P: RgbPropKeyExt> {
    fn is_opret_host(&self) -> bool { self.proprietary_contains(&P::opret_host()) }

    fn is_tapret_host(&self) -> bool { self.proprietary_contains(&P::tapret_host()) }

    fn set_opret_host(&mut self) -> bool { self.proprietary_push(P::opret_host(), vec![]).is_err() }

    fn set_tapret_host(&mut self) -> bool {
        self.proprietary_push(P::tapret_host(), vec![]).is_err()
    }

    /// Returns valid tapret commitment from the [`PSBT_OUT_TAPRET_COMMITMENT`]
    /// key, if present. If the commitment is absent or invalid, returns
    /// [`TapretKeyError::NoCommitment`].
    fn tapret_commitment(&self) -> Result<TapretCommitment, TapretKeyError> {
        let data = self
            .proprietary_get(&P::tapret_commitment())
            .ok_or(TapretKeyError::NoCommitment)?;
        TapretCommitment::from_strict_serialized::<U16>(
            Confined::try_from(data.to_vec()).map_err(|_| TapretKeyError::InvalidCommitment)?,
        )
        .map_err(|_| TapretKeyError::InvalidCommitment)
    }

    /// Assigns value of the opreturn commitment to this PSBT output, by
    /// adding [`PSBT_OUT_OPRET_COMMITMENT`] proprietary key containing the
    /// 32-byte commitment as its value. Also modifies the output script and removes
    /// [`PSBT_OUT_OPRET_HOST`] key.
    ///
    /// Opret commitment can be set only once.
    ///
    /// Errors with [`OpretKeyError::OutputAlreadyHasCommitment`] if the
    /// commitment is already present in the output.
    ///
    /// Errors if output script is not OP_RETURN script or opret commitments are not
    /// enabled for this output.
    fn opret_commit(&mut self, commitment: mpc::Commitment) -> Result<(), OpretKeyError> {
        if !self.is_opret_host() {
            return Err(OpretKeyError::OpretProhibited);
        }
        self.proprietary_push(P::opret_commitment(), commitment.to_vec())
            .map_err(|_| OpretKeyError::OutputAlreadyHasCommitment)?;
        self.proprietary_remove(&P::opret_host());
        Ok(())
    }

    fn get_internal_pk(&self) -> Option<UntweakedPublicKey>;

    fn is_tap_tree_empty(&self) -> bool;

    fn set_tap_tree(&mut self, script_commitment: &ScriptBuf);

    /// Assigns value of the tapreturn commitment to this PSBT output, by
    /// adding [`PSBT_OUT_TAPRET_COMMITMENT`] and [`PSBT_OUT_TAPRET_PROOF`]
    /// proprietary keys containing the 32-byte commitment as its proof.
    ///
    /// Errors with [`TapretKeyError::OutputAlreadyHasCommitment`] if the
    /// commitment is already present in the output, and with
    /// [`TapretKeyError::TapretProhibited`] if tapret commitments are not
    /// enabled for this output.
    fn tapret_commit(
        &mut self,
        commitment: mpc::Commitment,
    ) -> Result<TapretProof, TapretKeyError> {
        if !self.is_tapret_host() {
            return Err(TapretKeyError::TapretProhibited);
        }

        // TODO #10: support non-empty tap trees
        if !self.is_tap_tree_empty() {
            return Err(TapretKeyError::TapTreeNonEmpty);
        }
        let nonce = 0;
        let tapret_commitment = &TapretCommitment::with(commitment, nonce);
        let script_commitment = tapret_commitment.commit();

        self.set_tap_tree(&script_commitment);

        let internal_pk = self
            .get_internal_pk()
            .ok_or(TapretKeyError::NoInternalKey)?;
        let tapret_proof = TapretProof {
            path_proof: TapretPathProof::root(nonce),
            internal_pk,
        };

        let tapret_proof_serialized = tapret_proof
            .to_strict_serialized::<U16>()
            .expect("tapret proof too long")
            .to_vec();
        self.proprietary_push(P::tapret_commitment(), tapret_commitment.to_vec())
            .and_then(|_| self.proprietary_push(P::tapret_proof(), tapret_proof_serialized))
            .map_err(|_| TapretKeyError::OutputAlreadyHasCommitment)?;
        self.proprietary_remove(&P::tapret_host());

        Ok(tapret_proof)
    }

    fn bip32_derivation_terminals(&self) -> Vec<Terminal>;

    fn tap_bip32_derivation_terminals(&self) -> Vec<Terminal>;

    fn terminal_derivation(&self) -> Option<Terminal> {
        let terminal = self
            .bip32_derivation_terminals()
            .into_iter()
            .chain(self.tap_bip32_derivation_terminals())
            .collect::<BTreeSet<_>>();
        if terminal.len() != 1 {
            return None;
        }
        terminal.first().copied()
    }

    fn proprietary_mpc_messages<'a>(&'a self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + 'a;

    /// Returns [`mpc::MessageMap`] constructed from the proprietary key data.
    fn mpc_message_map(&self) -> Result<mpc::MessageMap, MpcPsbtError> {
        let map = self
            .proprietary_mpc_messages()
            .map(|(protocol_id_bytes, message_bytes)| {
                Ok((
                    ProtocolId::copy_from_slice(protocol_id_bytes)?,
                    Message::copy_from_slice(message_bytes)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, MpcPsbtError>>()?;
        Confined::try_from(map).map_err(MpcPsbtError::from)
    }

    /// Returns a valid LNPBP-4 entropy value, if present.
    ///
    /// We do not error on invalid data in order to support future update of
    /// this proprietary key to a standard one. In this case, the invalid
    /// data will be filtered at the moment of PSBT deserialization and this
    /// function will return `None` only in situations when the key is absent.
    fn mpc_entropy(&self) -> Option<u64> {
        let key = P::mpc_entropy();
        let data = self.proprietary_get(&key)?;
        if data.len() != 8 {
            return None;
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(data);
        Some(u64::from_le_bytes(buf))
    }

    fn mpc_min_tree_depth(&self) -> Option<u8> {
        let key = P::mpc_min_tree_depth();
        let data = self.proprietary_get(&key)?;
        if data.len() != 1 {
            return None;
        }
        Some(data[0])
    }

    /// Sets MPC entropy value.
    ///
    /// # Returns
    ///
    /// `true`, if the entropy was set successfully, `false` if this entropy
    /// value was already set.
    ///
    /// # Errors
    ///
    /// If the entropy was already set with a different value than the provided
    /// one.
    fn set_mpc_entropy(&mut self, entropy: u64) -> Result<bool, MpcPsbtError> {
        if self.proprietary_contains(&P::mpc_commitment()) {
            return Err(MpcPsbtError::Finalized);
        }
        let key = P::mpc_entropy();
        let val = entropy.to_le_bytes().to_vec();
        if let Some(v) = self.proprietary_get(&key) {
            if v != val {
                return Err(MpcPsbtError::InvalidKeyValue);
            }
            return Ok(false);
        }
        self.proprietary_push(key, val)?;
        Ok(true)
    }

    /// Sets MPC [`Message`] for the given [`ProtocolId`].
    ///
    /// # Returns
    ///
    /// `true`, if the message was set successfully, `false` if this message was
    /// already present for this protocol.
    ///
    /// # Errors
    ///
    /// If the key for the given [`ProtocolId`] is already present and the
    /// message is different.
    fn set_mpc_message(
        &mut self,
        protocol_id: ProtocolId,
        message: Message,
    ) -> Result<bool, MpcPsbtError> {
        if self.proprietary_contains(&P::mpc_commitment()) {
            return Err(MpcPsbtError::Finalized);
        }
        let key = P::mpc_message(protocol_id);
        let val = message.to_vec();
        if let Some(v) = self.proprietary_get(&key) {
            if v != val {
                return Err(MpcPsbtError::InvalidKeyValue);
            }
            return Ok(false);
        }
        self.proprietary_push(key, val)?;
        Ok(true)
    }

    fn mpc_commit(&mut self) -> Result<(Commitment, mpc::MerkleBlock), MpcPsbtError> {
        let messages = self.mpc_message_map()?;
        let min_depth = self
            .mpc_min_tree_depth()
            .map(u5::with)
            .unwrap_or(MPC_MINIMAL_DEPTH);
        let source = mpc::MultiSource {
            min_depth,
            messages,
            static_entropy: self.mpc_entropy(),
        };
        let merkle_tree = mpc::MerkleTree::try_commit(&source)?;
        let entropy = merkle_tree.entropy();
        self.set_mpc_entropy(entropy)?;
        let commitment = merkle_tree.commit_id();
        let mpc_proof = mpc::MerkleBlock::from(merkle_tree);
        let mpc_proof_serialized = mpc_proof.to_strict_serialized::<U32>().expect("max length");

        self.proprietary_push(P::mpc_commitment(), commitment.to_vec())
            .and_then(|_| {
                self.proprietary_push(P::mpc_proof(), mpc_proof_serialized.to_unconfined())
            })
            .map_err(|_| MpcPsbtError::OutputAlreadyHasCommitment)?;

        Ok((commitment, mpc_proof))
    }

    fn proprietary_push(&mut self, key: P, value: Vec<u8>) -> Result<(), MpcPsbtError> {
        if self.proprietary_contains(&key) {
            return Err(MpcPsbtError::KeyAlreadyPresent);
        }
        self.proprietary_insert(key, value);
        Ok(())
    }

    fn proprietary_insert(&mut self, key: P, value: Vec<u8>);

    fn proprietary_contains_key(&self, key: &P) -> bool;

    fn proprietary_contains(&self, key: &P) -> bool { self.proprietary_contains_key(key) }

    fn proprietary_get_value(&self, key: &P) -> Option<&[u8]>;

    fn proprietary_get(&self, key: &P) -> Option<&[u8]> { self.proprietary_get_value(key) }

    fn proprietary_remove(&mut self, key: &P);
}

#[allow(clippy::result_large_err)]
pub trait RgbPsbtExt<P: RgbPropKeyExt, O: RgbOutExt<P>> {
    fn get_txid(&self) -> Txid;

    fn modifiable_outputs(&self) -> bool;

    fn set_as_unmodifiable(&mut self);

    fn unsigned_tx(&self) -> Transaction;

    fn set_opret_host(&mut self) -> bool;

    fn dbc_output<D: DbcPsbtProof>(&self) -> Option<&O>;

    fn dbc_output_mut<D: DbcPsbtProof>(&mut self) -> Option<(usize, &mut O)>;

    fn dbc_commit<D: DbcPsbtProof>(&mut self) -> Result<(mpc::MerkleBlock, D), DbcPsbtError>
    where Self: std::marker::Sized {
        if self.modifiable_outputs() {
            return Err(DbcPsbtError::TxOutputsModifiable);
        }

        D::dbc_commit(self)
    }

    fn set_opret_commitment(&mut self, idx: usize);

    fn set_tapret_commitment(&mut self, idx: usize);

    fn rgb_embed(&mut self, batch: Batch) -> Result<(), EmbedError> {
        for transition in batch {
            self.push_rgb_transition(transition)?;
        }
        Ok(())
    }

    fn rgb_commit(&mut self) -> Result<Fascia, CommitError>
    where Self: std::marker::Sized {
        // Convert RGB data to MPCs? Or should we do it at the moment we add them... No,
        // since we may require more DBC methods with each additional state transition
        let bundles = self.rgb_bundles_to_mpc()?;
        // DBC commitment for the correct close method
        let close_method = self
            .rgb_close_method()?
            .ok_or(RgbPsbtError::NoCloseMethod)?;
        let (merkle_block, dbc_proof) = match close_method {
            CloseMethod::TapretFirst => self
                .dbc_commit::<TapretProof>()
                .map(|(mb, proof)| (mb, proof.into()))?,
            CloseMethod::OpretFirst => self
                .dbc_commit::<OpretProof>()
                .map(|(mb, proof)| (mb, proof.into()))?,
        };
        let witness = PubWitness::with(self.unsigned_tx());
        let seal_witness = SealWitness::new(witness, merkle_block, dbc_proof);
        Ok(Fascia {
            seal_witness,
            bundles,
        })
    }

    fn proprietary_rgb_contract_consumer_keys<'a>(&'a self) -> impl Iterator<Item = &'a [u8]> + 'a;

    fn rgb_contract_ids(&self) -> Result<BTreeSet<ContractId>, FromSliceError> {
        self.proprietary_rgb_contract_consumer_keys()
            .map(ContractId::copy_from_slice)
            .collect()
    }

    fn rgb_contract_consumers(
        &self,
        contract_id: ContractId,
    ) -> Result<BTreeMap<Opout, OpId>, RgbPsbtError> {
        let Some(data) = self.proprietary_get(&P::rgb_consumed_by(contract_id)) else {
            return Ok(BTreeMap::new());
        };
        Ok(OpoutAndOpids::deserialize(data)?.into_inner())
    }

    fn rgb_transition(&self, opid: OpId) -> Result<Option<Transition>, RgbPsbtError> {
        let Some(data) = self.proprietary_get(&P::rgb_transition(opid)) else {
            return Ok(None);
        };
        let data = Confined::try_from_iter(data.iter().copied())?;
        let transition = Transition::from_strict_serialized::<U24>(data)?;
        Ok(Some(transition))
    }

    fn rgb_close_method(&self) -> Result<Option<CloseMethod>, RgbPsbtError> {
        let Some(m) = self.proprietary_get(&P::rgb_close_method()) else {
            return Ok(None);
        };
        if m.len() == 1 {
            if let Ok(method) = CloseMethod::try_from(m[0]) {
                return Ok(Some(method));
            }
        }
        Err(RgbPsbtError::InvalidCloseMethod)
    }

    fn rgb_tapret_host_on_change(&self) -> bool {
        self.proprietary_contains(&P::rgb_tapret_host_on_change())
    }

    fn set_rgb_close_method(&mut self, close_method: CloseMethod) {
        let _ = self.proprietary_push(P::rgb_close_method(), vec![close_method as u8]);
    }

    fn set_rgb_tapret_host_on_change(&mut self) {
        let _ = self.proprietary_push(P::rgb_tapret_host_on_change(), vec![]);
    }

    /// Adds information about an RGB input allocation and the ID of the state
    /// transition spending it.
    ///
    /// # Returns
    ///
    /// `Ok(false)`, if the same opout under the same contract was already
    /// present with the provided state transition ID. `Ok(true)`, if the
    /// opout was successfully added.
    ///
    /// # Errors
    ///
    /// If the [`Opout`] already exists but it's referencing a different [`OpId`].
    fn set_rgb_contract_consumer(
        &mut self,
        contract_id: ContractId,
        opout: Opout,
        opid: OpId,
    ) -> Result<bool, RgbPsbtError> {
        let key = P::rgb_consumed_by(contract_id);
        if let Some(existing_data) = self.proprietary_get(&key) {
            let mut items = OpoutAndOpids::deserialize(existing_data)?;
            if let Some(existing_opid) = items.get(&opout) {
                if *existing_opid != opid {
                    return Err(RgbPsbtError::DoubleSpend);
                }
                return Ok(false);
            }
            items.insert(opout, opid);
            self.proprietary_insert(key, items.serialize());
        } else {
            let items = OpoutAndOpids::new(bmap![opout => opid]);
            let _ = self.proprietary_push(key, items.serialize());
        }
        Ok(true)
    }

    fn push_rgb_transition(&mut self, mut transition: Transition) -> Result<bool, RgbPsbtError> {
        let opid = transition.id();

        let prev_transition = self.rgb_transition(opid)?;
        if let Some(ref prev_transition) = prev_transition {
            transition.merge_reveal(prev_transition).map_err(|err| {
                RgbPsbtError::UnrelatedTransitions(prev_transition.id(), opid, err)
            })?;
        }
        let serialized_transition = transition
            .to_strict_serialized::<U24>()
            .map_err(|_| RgbPsbtError::TransitionTooBig(opid))?;

        // Since we update transition it's ok to ignore the fact that it previously
        // existed
        let _ = self.proprietary_push(P::rgb_transition(opid), serialized_transition.release());

        for opout in transition.inputs() {
            self.set_rgb_contract_consumer(transition.contract_id, opout, opid)?;
        }

        Ok(prev_transition.is_none())
    }

    fn rgb_bundles(&self) -> Result<BTreeMap<ContractId, TransitionBundle>, RgbPsbtError> {
        let mut map = BTreeMap::new();
        for contract_id in self.rgb_contract_ids()? {
            let contract_consumers = self.rgb_contract_consumers(contract_id)?;
            if contract_consumers.is_empty() {
                return Err(RgbPsbtError::NoContractConsumers);
            }
            let inputs_len = contract_consumers.len();
            let input_map = NonEmptyOrdMap::try_from(contract_consumers)
                .map_err(|_| RgbPsbtError::InvalidInputsNumber(inputs_len))?;
            let mut transitions_map: HashMap<OpId, Transition> = HashMap::new();
            for opid in input_map.values() {
                if let Some(transition) = self.rgb_transition(*opid)? {
                    transitions_map.insert(*opid, transition);
                }
            }
            let known_transitions_len = transitions_map.values().len();
            let mut known_transitions: SmallVec<KnownTransition> =
                SmallVec::with_capacity(known_transitions_len);
            insert_transitions_sorted(&transitions_map, &mut known_transitions)?;

            let bundle = TransitionBundle {
                input_map,
                known_transitions: Confined::try_from(known_transitions.release()).map_err(
                    |_| RgbPsbtError::InvalidTransitionsNumber(contract_id, known_transitions_len),
                )?,
            };
            map.insert(contract_id, bundle);
        }
        Ok(map)
    }

    fn outputs_iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut O>
    where O: 'a;

    fn rgb_bundles_to_mpc(
        &mut self,
    ) -> Result<Confined<BTreeMap<ContractId, TransitionBundle>, 1, U24>, RgbPsbtError> {
        let bundles = self.rgb_bundles()?;

        let close_method = self
            .rgb_close_method()?
            .ok_or(RgbPsbtError::NoCloseMethod)?;

        let host = self
            .outputs_iter_mut()
            .find(|output| match close_method {
                CloseMethod::OpretFirst => output.is_opret_host(),
                CloseMethod::TapretFirst => output.is_tapret_host(),
            })
            .ok_or(RgbPsbtError::NoHostOutput(close_method))?;

        for (contract_id, bundle) in &bundles {
            let protocol_id = mpc::ProtocolId::from(*contract_id);
            let message = mpc::Message::from(bundle.bundle_id());
            host.set_mpc_message(protocol_id, message)?;
        }

        let map = Confined::try_from(bundles).map_err(|_| RgbPsbtError::NoContracts)?;

        Ok(map)
    }

    fn proprietary_insert(&mut self, key: P, value: Vec<u8>);

    fn proprietary_push(&mut self, key: P, value: Vec<u8>) -> Result<(), MpcPsbtError> {
        if self.proprietary_contains(&key) {
            return Err(MpcPsbtError::KeyAlreadyPresent);
        }
        self.proprietary_insert(key, value);
        Ok(())
    }

    fn proprietary_contains_key(&self, key: &P) -> bool;

    fn proprietary_contains(&self, key: &P) -> bool { self.proprietary_contains_key(key) }

    fn proprietary_get_value(&self, key: &P) -> Option<&[u8]>;

    fn proprietary_get(&self, key: &P) -> Option<&[u8]> { self.proprietary_get_value(key) }
}
