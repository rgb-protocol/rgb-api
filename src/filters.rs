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

use rgbstd::contract::AssignmentsFilter;
use rgbstd::{Outpoint, Txid};

use crate::WalletProvider;

#[derive(Copy, Clone)]
pub enum Filter {
    Outpoints,
    Unspent,
    Witness,
}

pub struct WalletFilter<'wallet, W: WalletProvider + ?Sized> {
    wallet: &'wallet W,
    filter: Filter,
}

impl<'wallet, W: WalletProvider + ?Sized> WalletFilter<'wallet, W> {
    pub fn new(wallet: &'wallet W, filter: Filter) -> WalletFilter<'wallet, W> {
        Self { wallet, filter }
    }
}

impl<W: WalletProvider + ?Sized> Copy for WalletFilter<'_, W> {}
impl<W: WalletProvider + ?Sized> Clone for WalletFilter<'_, W> {
    fn clone(&self) -> Self { *self }
}

impl<W: WalletProvider + ?Sized> AssignmentsFilter for WalletFilter<'_, W> {
    fn should_include(&self, outpoint: impl Into<Outpoint>, witness_id: Option<Txid>) -> bool {
        match self.filter {
            Filter::Outpoints => self.wallet.has_outpoint(outpoint.into()),
            Filter::Unspent => self.wallet.is_unspent(outpoint.into()),
            Filter::Witness => self.wallet.should_include_witness(witness_id),
        }
    }
}
