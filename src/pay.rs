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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::Infallible;

use amplify::confinement::{Confined, U24};
use chrono::Utc;
use psrgbt::{RgbOutExt, RgbPropKeyExt, RgbPsbtExt, TapretKeyError, Terminal};
use rgbstd::containers::{Batch, BuilderSeal, Transfer};
use rgbstd::contract::{AllocatedState, AssignmentsFilter, BuilderError};
use rgbstd::invoice::{Amount, Beneficiary, InvoiceState, RgbInvoice};
use rgbstd::persistence::{IndexProvider, StashInconsistency, StashProvider, StateProvider, Stock};
use rgbstd::rgbcore::dbc::tapret::{TapretCommitment, TapretProof};
use rgbstd::rgbcore::dbc::Proof;
use rgbstd::rgbcore::seals::txout::{CloseMethod, ExplicitSeal};
use rgbstd::rgbcore::secp256k1::rand;
use rgbstd::validation::WitnessOrdProvider;
use rgbstd::{
    AssignmentType, ContractId, GraphSeal, Opout, Outpoint, OutputSeal, RevealedData, Transition,
    TransitionType, Txid,
};

use crate::filters::{Filter, WalletFilter};
use crate::invoice::NonFungible;
use crate::validation::WitnessResolverError;
use crate::vm::WitnessOrd;
use crate::{CompletionError, CompositionError, PayError, WalletError};

#[derive(Copy, Clone, PartialEq, Debug)]
pub struct TxParams {
    pub fee_sats: u64,
    pub lock_time: Option<u32>,
    pub seq_no: u32,
    pub change_shift: bool,
    pub change_keychain: u8,
}

impl TxParams {
    pub fn with(fee_sats: u64) -> Self {
        TxParams {
            fee_sats,
            lock_time: None,
            seq_no: 0,
            change_shift: true,
            change_keychain: 1,
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct TransferParams {
    pub tx: TxParams,
    pub min_amount: u64,
}

impl TransferParams {
    pub fn with(fee_sats: u64, min_amount_sats: u64) -> Self {
        TransferParams {
            tx: TxParams::with(fee_sats),
            min_amount: min_amount_sats,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct PsbtMeta {
    pub beneficiary_vout: Option<u32>,
    pub change_vout: Option<u32>,
}

struct PaymentContext {
    contract_id: ContractId,
    assignment_type: AssignmentType,
    transition_type: TransitionType,
}

struct ContractOutpointsFilter<
    'stock,
    'wallet,
    W: WalletProvider + ?Sized,
    S: StashProvider,
    H: StateProvider,
    I: IndexProvider,
> {
    contract_id: ContractId,
    stock: &'stock Stock<S, H, I>,
    wallet: &'wallet W,
}

impl<W: WalletProvider + ?Sized, S: StashProvider, H: StateProvider, I: IndexProvider>
    AssignmentsFilter for ContractOutpointsFilter<'_, '_, W, S, H, I>
{
    fn should_include(&self, outpoint: impl Into<Outpoint>, witness_id: Option<Txid>) -> bool {
        let outpoint = outpoint.into();
        if !self
            .wallet
            .filter_unspent()
            .should_include(outpoint, witness_id)
        {
            return false;
        }
        matches!(self.stock.contract_assignments_for(self.contract_id, [outpoint]), Ok(list) if !list.is_empty())
    }
}

#[allow(clippy::result_large_err)]
fn validate_contract_and_invoice<S: StashProvider, H: StateProvider, I: IndexProvider>(
    stock: &Stock<S, H, I>,
    invoice: &RgbInvoice,
) -> Result<PaymentContext, CompositionError> {
    let contract_id = invoice.contract.ok_or(CompositionError::NoContract)?;
    let contract = stock
        .contract_data(contract_id)
        .map_err(|e| e.to_string())?;

    if let Some(invoice_schema) = invoice.schema {
        if invoice_schema != contract.schema.schema_id() {
            return Err(CompositionError::InvalidSchema);
        }
    }

    let contract_genesis = stock
        .as_stash_provider()
        .genesis(contract_id)
        .map_err(|_| CompositionError::UnknownContract)?;
    let contract_chain_net = contract_genesis.chain_net;
    let invoice_chain_net = invoice.chain_network();
    if contract_chain_net != invoice_chain_net {
        return Err(CompositionError::InvoiceBeneficiaryWrongChainNet(
            invoice_chain_net,
            contract_chain_net,
        ));
    }

    if let Some(expiry) = invoice.expiry {
        if expiry < Utc::now().timestamp() {
            return Err(CompositionError::InvoiceExpired);
        }
    }

    let Some(ref assignment_state) = invoice.assignment_state else {
        return Err(CompositionError::NoAssignmentState);
    };

    let invoice_assignment_type = invoice
        .assignment_name
        .as_ref()
        .map(|n| contract.schema.assignment_type(n.clone()));
    let assignment_type = invoice_assignment_type
        .as_ref()
        .or_else(|| {
            let assignment_types = contract
                .schema
                .assignment_types_for_state(assignment_state.clone().into());
            if assignment_types.len() == 1 {
                Some(assignment_types[0])
            } else {
                contract
                    .schema
                    .default_assignment
                    .as_ref()
                    .filter(|&assignment| assignment_types.contains(&assignment))
            }
        })
        .ok_or(CompositionError::NoAssignmentType)?;
    let transition_type = contract
        .schema
        .default_transition_for_assignment(assignment_type);

    Ok(PaymentContext {
        contract_id,
        assignment_type: *assignment_type,
        transition_type,
    })
}

#[allow(clippy::result_large_err)]
fn select_state_for_invoice<S: StashProvider, H: StateProvider, I: IndexProvider>(
    stock: &Stock<S, H, I>,
    invoice: &RgbInvoice,
    context: &PaymentContext,
    filter: &impl AssignmentsFilter,
) -> Result<BTreeSet<OutputSeal>, CompositionError> {
    let contract = stock
        .contract_data(context.contract_id)
        .map_err(|e| e.to_string())?;

    let Some(ref assignment_state) = invoice.assignment_state else {
        return Err(CompositionError::NoAssignmentState);
    };

    let prev_outputs = match assignment_state {
        InvoiceState::Amount(amount) => {
            let mut state: BTreeMap<_, Vec<Amount>> = BTreeMap::new();
            for a in contract.fungible_raw(context.assignment_type, filter)? {
                state.entry(a.seal).or_default().push(a.state);
            }
            let mut state: Vec<_> = state
                .into_iter()
                .map(|(seal, vals)| (vals.iter().copied().sum::<Amount>(), seal, vals))
                .collect();
            state.sort_by_key(|(sum, _, _)| *sum);
            let mut sum = Amount::ZERO;
            let selection = state
                .iter()
                .rev()
                .take_while(|(val, _, _)| {
                    if sum >= *amount {
                        false
                    } else {
                        sum += *val;
                        true
                    }
                })
                .map(|(_, seal, _)| *seal)
                .collect::<BTreeSet<_>>();

            if sum < *amount {
                bset![]
            } else {
                selection
            }
        }
        InvoiceState::Data(NonFungible::FractionedToken(allocation)) => {
            let data_state = RevealedData::from(*allocation);
            contract
                .data_raw(context.assignment_type, filter)?
                .filter(|x| x.state == data_state)
                .map(|x| x.seal)
                .collect::<BTreeSet<_>>()
        }
        InvoiceState::Void => contract
            .rights_raw(context.assignment_type, filter)?
            .map(|x| x.seal)
            .collect::<BTreeSet<_>>(),
    };

    Ok(prev_outputs)
}

#[allow(clippy::result_large_err)]
fn build_main_transition<S: StashProvider, H: StateProvider, I: IndexProvider>(
    stock: &Stock<S, H, I>,
    invoice: &RgbInvoice,
    context: &PaymentContext,
    prev_outputs: &BTreeSet<OutputSeal>,
    meta: &PsbtMeta,
) -> Result<Transition, CompositionError> {
    let Some(ref assignment_state) = invoice.assignment_state else {
        return Err(CompositionError::NoAssignmentState);
    };

    let builder_seal = match (invoice.beneficiary.into_inner(), meta.beneficiary_vout) {
        (Beneficiary::BlindedSeal(seal), None) => BuilderSeal::Concealed(seal),
        (Beneficiary::BlindedSeal(_), Some(_)) => {
            return Err(CompositionError::BeneficiaryVout);
        }
        (Beneficiary::WitnessVout(_, _), Some(vout)) => {
            let seal = GraphSeal::with_blinded_vout(vout, rand::random());
            BuilderSeal::Revealed(seal)
        }
        (Beneficiary::WitnessVout(_, _), None) => {
            return Err(CompositionError::NoBeneficiaryOutput);
        }
    };

    let mut main_builder = stock
        .transition_builder_raw(context.contract_id, context.transition_type)
        .map_err(|e| e.to_string())?;

    let mut sum_inputs = Amount::ZERO;
    let mut data_inputs = vec![];
    for (_output, list) in stock
        .contract_assignments_for(context.contract_id, prev_outputs.iter().copied())
        .map_err(|e| e.to_string())?
    {
        for (opout, state) in list {
            main_builder = main_builder.add_input(opout, state.clone())?;
            if opout.ty != context.assignment_type {
                let seal = create_change_output_seal(opout.ty, meta)?;
                main_builder = main_builder.add_owned_state_raw(opout.ty, seal, state)?;
            } else if let AllocatedState::Amount(value) = state {
                sum_inputs += value.into();
            } else if let AllocatedState::Data(value) = state {
                data_inputs.push(value);
            }
        }
    }

    // Add payments to beneficiary and change
    match assignment_state {
        InvoiceState::Amount(amt) => {
            // Pay beneficiary
            if sum_inputs < *amt {
                return Err(CompositionError::InsufficientState);
            }

            if *amt > Amount::ZERO {
                main_builder = main_builder.add_fungible_state_raw(
                    context.assignment_type,
                    builder_seal,
                    *amt,
                )?;
            }

            // Pay change
            if sum_inputs > *amt {
                let change_seal = create_change_output_seal(context.assignment_type, meta)?;
                main_builder = main_builder.add_fungible_state_raw(
                    context.assignment_type,
                    change_seal,
                    sum_inputs - *amt,
                )?;
            }
        }
        InvoiceState::Data(data) => match data {
            NonFungible::FractionedToken(allocation) => {
                let lookup_state = RevealedData::from(*allocation);
                if !data_inputs.into_iter().any(|x| x == lookup_state) {
                    return Err(CompositionError::InsufficientState);
                }

                main_builder = main_builder.add_data_raw(
                    context.assignment_type,
                    builder_seal,
                    lookup_state,
                )?;
            }
        },
        InvoiceState::Void => {
            main_builder = main_builder.add_rights_raw(context.assignment_type, builder_seal)?;
        }
    }

    if !main_builder.has_inputs() {
        return Err(CompositionError::InsufficientState);
    }

    let transition = main_builder.complete_transition()?;
    Ok(transition)
}

#[allow(clippy::result_large_err)]
fn create_change_output_seal(
    assignment_type: AssignmentType,
    meta: &PsbtMeta,
) -> Result<BuilderSeal<GraphSeal>, CompositionError> {
    let vout = meta
        .change_vout
        .ok_or(CompositionError::NoExtraOrChange(assignment_type))?;
    let seal = GraphSeal::with_blinded_vout(vout, rand::random());
    Ok(BuilderSeal::Revealed(seal))
}

#[allow(clippy::result_large_err)]
fn build_extra_transitions<S: StashProvider, H: StateProvider, I: IndexProvider>(
    stock: &Stock<S, H, I>,
    contract_id: ContractId,
    prev_outputs: &BTreeSet<OutputSeal>,
    meta: &PsbtMeta,
) -> Result<Confined<Vec<Transition>, 0, { U24 - 1 }>, CompositionError> {
    let prev_outputs_set = prev_outputs
        .iter()
        .copied()
        .collect::<HashSet<OutputSeal>>();

    // Enumerate state for other contracts
    let mut extra_state =
        HashMap::<ContractId, HashMap<OutputSeal, HashMap<Opout, AllocatedState>>>::new();
    for id in stock
        .contracts_assigning(prev_outputs_set.iter().copied())
        .map_err(|e| e.to_string())?
    {
        // Skip current contract
        if id == contract_id {
            continue;
        }
        let state = stock
            .contract_assignments_for(id, prev_outputs_set.iter().copied())
            .map_err(|e| e.to_string())?;
        let entry = extra_state.entry(id).or_default();
        for (seal, assigns) in state {
            entry.entry(seal).or_default().extend(assigns);
        }
    }

    // Construct transitions for extra state
    let mut extras = Confined::<Vec<_>, 0, { U24 - 1 }>::with_capacity(extra_state.len());
    for (id, seal_map) in extra_state {
        let schema = stock
            .as_stash_provider()
            .contract_schema(id)
            .map_err(|_| BuilderError::Inconsistency(StashInconsistency::ContractAbsent(id)))?;

        for (_output, assigns) in seal_map {
            for (opout, state) in assigns {
                let transition_type = schema.default_transition_for_assignment(&opout.ty);

                let mut extra_builder = stock
                    .transition_builder_raw(id, transition_type)
                    .map_err(|e| e.to_string())?;

                let seal = create_change_output_seal(opout.ty, meta)?;
                extra_builder = extra_builder
                    .add_input(opout, state.clone())?
                    .add_owned_state_raw(opout.ty, seal, state)?;

                if !extra_builder.has_inputs() {
                    continue;
                }
                let transition = extra_builder.complete_transition()?;
                extras
                    .push(transition)
                    .map_err(|_| CompositionError::TooManyExtras)?;
            }
        }
    }

    Ok(extras)
}

pub trait WalletProvider {
    type P: RgbPropKeyExt;
    type O: RgbOutExt<Self::P>;
    type Psbt: RgbPsbtExt<Self::P, Self::O>;

    fn close_method(&self) -> CloseMethod;

    fn filter_outpoints(&self) -> impl AssignmentsFilter + Clone {
        WalletFilter::new(self, Filter::Outpoints)
    }

    fn filter_unspent(&self) -> impl AssignmentsFilter + Clone {
        WalletFilter::new(self, Filter::Unspent)
    }

    fn filter_witnesses(&self) -> impl AssignmentsFilter + Clone {
        WalletFilter::new(self, Filter::Witness)
    }

    fn is_unspent(&self, outpoint: Outpoint) -> bool;

    fn has_outpoint(&self, outpoint: Outpoint) -> bool;

    fn should_include_witness(&self, witness_id: Option<Txid>) -> bool;

    fn add_tapret_tweak(
        &mut self,
        terminal: Terminal,
        tweak: TapretCommitment,
    ) -> Result<(), Infallible>;

    fn try_add_tapret_tweak(
        &mut self,
        transfer: Transfer,
        txid: &Txid,
    ) -> Result<(), Box<WalletError>>;

    #[allow(clippy::result_large_err)]
    fn pay<
        S: StashProvider,
        H: StateProvider,
        I: IndexProvider,
        P: RgbPropKeyExt,
        O: RgbOutExt<P>,
    >(
        &mut self,
        stock: &mut Stock<S, H, I>,
        invoice: &RgbInvoice,
        params: TransferParams,
    ) -> Result<(Self::Psbt, PsbtMeta, Transfer), PayError> {
        let (mut psbt, meta) = self.construct_psbt_rgb::<S, H, I, P, O>(stock, invoice, params)?;
        // ... here we pass PSBT around signers, if necessary
        let transfer = match self.transfer(stock, invoice, &mut psbt, meta.beneficiary_vout) {
            Ok(transfer) => transfer,
            Err(e) => return Err(PayError::Completion(e)),
        };
        Ok((psbt, meta, transfer))
    }

    #[allow(clippy::result_large_err)]
    fn create_psbt(
        &mut self,
        invoice: &RgbInvoice,
        close_method: CloseMethod,
        coins: impl IntoIterator<Item = Outpoint>,
        params: TransferParams,
    ) -> Result<(Self::Psbt, PsbtMeta), CompositionError>;

    #[allow(clippy::result_large_err)]
    fn construct_psbt_rgb<
        S: StashProvider,
        H: StateProvider,
        I: IndexProvider,
        P: RgbPropKeyExt,
        O: RgbOutExt<P>,
    >(
        &mut self,
        stock: &Stock<S, H, I>,
        invoice: &RgbInvoice,
        params: TransferParams,
    ) -> Result<(Self::Psbt, PsbtMeta), CompositionError> {
        let close_method = self.close_method();

        // 1. Validate contract and invoice
        let context = validate_contract_and_invoice(stock, invoice)?;

        // 2. Select state for the invoice
        let filter = ContractOutpointsFilter {
            contract_id: context.contract_id,
            stock,
            wallet: self,
        };
        let prev_outputs = select_state_for_invoice(stock, invoice, &context, &filter)?;

        if prev_outputs.is_empty() {
            return Err(CompositionError::InsufficientState);
        }

        let prev_outpoints = prev_outputs
            .iter()
            .map(|o| Outpoint::new(o.txid, o.vout.to_u32()));

        let (mut psbt, meta) = self.create_psbt(invoice, close_method, prev_outpoints, params)?;

        // 3. Build main transition
        let main = build_main_transition(stock, invoice, &context, &prev_outputs, &meta)?;

        // 4. Build extra transitions for other contracts
        let extras = build_extra_transitions(stock, context.contract_id, &prev_outputs, &meta)?;

        let mut batch = Batch { main, extras };
        batch.set_priority(u64::MAX);

        psbt.set_rgb_close_method(close_method);
        psbt.set_as_unmodifiable();
        psbt.rgb_embed(batch)?;
        Ok((psbt, meta))
    }

    #[allow(clippy::result_large_err)]
    fn transfer<S: StashProvider, H: StateProvider, P: IndexProvider>(
        &mut self,
        stock: &mut Stock<S, H, P>,
        invoice: &RgbInvoice,
        psbt: &mut Self::Psbt,
        beneficiary_vout: Option<u32>,
    ) -> Result<Transfer, CompletionError> {
        let contract_id = invoice.contract.ok_or(CompletionError::NoContract)?;

        let fascia = psbt.rgb_commit()?;
        if matches!(fascia.seal_witness.dbc_proof.method(), CloseMethod::TapretFirst) {
            // save tweak only if tapret commitment is on the bitcoin change
            if psbt.rgb_tapret_host_on_change() {
                let output = psbt
                    .dbc_output::<TapretProof>()
                    .ok_or(TapretKeyError::NotTaprootOutput)?;
                let terminal = output
                    .terminal_derivation()
                    .ok_or_else(|| CompletionError::InconclusiveDerivation)?;
                let tapret_commitment = output.tapret_commitment()?;
                self.add_tapret_tweak(terminal, tapret_commitment)?;
            }
        }

        let witness_id = psbt.get_txid();
        let (beneficiary1, beneficiary2) = match invoice.beneficiary.into_inner() {
            Beneficiary::WitnessVout(_, _) => {
                let seal = ExplicitSeal::new(Outpoint::new(witness_id, beneficiary_vout.unwrap()));
                (vec![], vec![seal])
            }
            Beneficiary::BlindedSeal(seal) => (vec![seal], vec![]),
        };

        struct FasciaResolver {
            witness_id: Txid,
        }
        impl WitnessOrdProvider for FasciaResolver {
            fn witness_ord(&self, witness_id: Txid) -> Result<WitnessOrd, WitnessResolverError> {
                assert_eq!(witness_id, self.witness_id);
                Ok(WitnessOrd::Tentative)
            }
        }

        stock
            .consume_fascia(fascia, FasciaResolver { witness_id })
            .map_err(|e| e.to_string())?;
        let transfer = stock
            .transfer(contract_id, beneficiary2, beneficiary1, [], None)
            .map_err(|e| e.to_string())?;

        Ok(transfer)
    }
}
