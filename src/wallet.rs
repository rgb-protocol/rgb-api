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

use psrgbt::{RgbOutExt, RgbPropKeyExt};
use rgbstd::containers::Transfer;
use rgbstd::contract::ContractOp;
use rgbstd::indexers::ResolveSpvProof;
#[cfg(feature = "sqlite")]
use rgbstd::persistence::sql::{self, SqlError, SqlIndex, SqlStash, SqlState};
use rgbstd::persistence::{IndexProvider, StashProvider, StateProvider, Stock, StockError};

use super::{
    CompletionError, CompositionError, ContractId, PayError, TransferParams, WalletProvider,
};
use crate::invoice::RgbInvoice;
use crate::pay::PsbtMeta;

#[cfg(feature = "sqlite")]
pub type SqliteRgbWallet<W> = RgbWallet<W, SqlStash, SqlState, SqlIndex>;

#[derive(Getters)]
pub struct RgbWallet<W: WalletProvider, S: StashProvider, H: StateProvider, I: IndexProvider> {
    stock: Stock<S, H, I>,
    wallet: W,
}

#[cfg(feature = "sqlite")]
impl<W: WalletProvider> RgbWallet<W, SqlStash, SqlState, SqlIndex> {
    pub fn from_sqlite(
        wallet: W,
        stock_path: impl AsRef<std::path::Path>,
    ) -> Result<Self, SqlError> {
        let stock = sql::open(stock_path)?;
        Ok(Self::new(stock, wallet))
    }
}

impl<W: WalletProvider, S: StashProvider, H: StateProvider, I: IndexProvider>
    RgbWallet<W, S, H, I>
{
    pub fn new(stock: Stock<S, H, I>, wallet: W) -> Self { Self { stock, wallet } }

    pub fn stock_mut(&mut self) -> &mut Stock<S, H, I> { &mut self.stock }

    pub fn wallet_mut(&mut self) -> &mut W { &mut self.wallet }

    pub fn history(&self, contract_id: ContractId) -> Result<Vec<ContractOp>, StockError<S, H, I>> {
        let contract = self.stock.contract_data(contract_id)?;
        let wallet = &self.wallet;
        Ok(contract.history(wallet.filter_outpoints(), wallet.filter_witnesses()))
    }

    #[allow(clippy::result_large_err)]
    pub fn pay<P: RgbPropKeyExt, O: RgbOutExt<P>>(
        &mut self,
        invoice: &RgbInvoice,
        params: TransferParams,
        spv_resolver: Option<&dyn ResolveSpvProof>,
    ) -> Result<(W::Psbt, PsbtMeta, Transfer), PayError> {
        self.wallet
            .pay::<S, H, I, P, O>(&mut self.stock, invoice, params, spv_resolver)
    }

    #[allow(clippy::result_large_err)]
    pub fn construct_psbt<P: RgbPropKeyExt, O: RgbOutExt<P>>(
        &mut self,
        invoice: &RgbInvoice,
        params: TransferParams,
    ) -> Result<(W::Psbt, PsbtMeta), CompositionError> {
        self.wallet
            .construct_psbt_rgb::<S, H, I, P, O>(&self.stock, invoice, params)
    }

    #[allow(clippy::result_large_err)]
    pub fn transfer(
        &mut self,
        invoice: &RgbInvoice,
        psbt: &mut W::Psbt,
        beneficiary_vout: Option<u32>,
        spv_resolver: Option<&dyn ResolveSpvProof>,
    ) -> Result<Transfer, CompletionError> {
        self.wallet
            .transfer(&mut self.stock, invoice, psbt, beneficiary_vout, spv_resolver)
    }
}
