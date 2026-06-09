// RGB smart contracts for Bitcoin & Lightning
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

#![allow(clippy::needless_update, clippy::result_large_err)] // Required by From derive macro

use std::fs;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;

use bpwallet::cli::{Args as BpArgs, Config, DescriptorOpts};
use bpwallet::{Network, Wallet, XpubDerivable};
use rgb::validation::ResolveWitness;
use rgb::{ChainNet, RgbDescr, SqliteRgbWallet, TapretKey, WalletError, WpkhDescr};
use rgbstd::indexers::{esplora_blocking, AnyResolver};
use rgbstd::persistence::sql::{self, SqliteStock};

use crate::Command;

#[derive(Args, Clone, PartialEq, Eq, Debug)]
#[group()]
pub struct DescrRgbOpts {
    /// Use tapret(KEY) descriptor as wallet.
    #[arg(long, global = true)]
    pub tapret_key_only: Option<XpubDerivable>,

    /// Use wpkh(KEY) descriptor as wallet.
    #[arg(long, global = true)]
    pub wpkh: Option<XpubDerivable>,
}

impl DescriptorOpts for DescrRgbOpts {
    type Descr = RgbDescr<XpubDerivable>;

    fn is_some(&self) -> bool { self.tapret_key_only.is_some() || self.wpkh.is_some() }

    fn descriptor(&self) -> Option<Self::Descr> {
        self.tapret_key_only
            .clone()
            .map(|xpub| RgbDescr::TapretKey(TapretKey::with_key(xpub)))
            .or(self
                .wpkh
                .clone()
                .map(|xpub| RgbDescr::Wpkh(WpkhDescr::with_key(xpub))))
    }
}

/// Command-line arguments
#[derive(Parser)]
#[derive(Clone, Eq, PartialEq, Debug)]
#[command(author, version, about)]
pub struct RgbArgs {
    #[clap(flatten)]
    pub inner: BpArgs<Command, DescrRgbOpts>,

    /// Specify blockchain height starting from which witness transactions
    /// should be checked for re-orgs
    #[clap(short = 'H', long, requires = "sync")]
    pub from_height: Option<u32>,
}

impl Deref for RgbArgs {
    type Target = BpArgs<Command, DescrRgbOpts>;
    #[inline]
    fn deref(&self) -> &Self::Target { &self.inner }
}

impl DerefMut for RgbArgs {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.inner }
}

impl Default for RgbArgs {
    fn default() -> Self { unreachable!() }
}

impl RgbArgs {
    /// Name of the SQLite database holding the stock, under the base dir.
    const STOCK_DB: &'static str = "stock.db";

    pub(crate) fn load_stock(
        &self,
        stock_path: impl ToOwned<Owned = PathBuf>,
    ) -> Result<SqliteStock, WalletError> {
        let stock_path = stock_path.to_owned();

        if self.verbose > 1 {
            eprint!("Loading stock from `{}` ... ", stock_path.display());
        }

        // `sql::open` creates and migrates the database when it is absent, so
        // the first run needs no separate initialisation path -- only the
        // containing directory has to exist.
        fs::create_dir_all(&stock_path)?;
        let mut stock = sql::open(stock_path.join(Self::STOCK_DB))?;

        if self.sync {
            let resolver = self.resolver()?;
            let from_height = self.from_height.unwrap_or(1);
            eprint!("Updating witness information starting from height {from_height} ... ");
            let res = stock.update_witnesses(resolver, from_height, vec![])?;
            eprint!("{} transactions were checked and updated", res.succeeded);
            if res.failed.is_empty() {
                eprintln!();
            } else {
                eprintln!(", {} resolution failures:", res.failed.len());
                for (witness_id, failure) in res.failed {
                    eprintln!(" - {witness_id}: {failure}");
                }
            }
        }

        if self.verbose > 1 {
            eprintln!("success");
        }

        Ok(stock)
    }

    pub fn rgb_stock(&self) -> Result<SqliteStock, WalletError> {
        let stock_path = self.general.base_dir();
        let stock = self.load_stock(stock_path)?;
        Ok(stock)
    }

    pub fn rgb_wallet(
        &self,
        config: &Config,
    ) -> Result<SqliteRgbWallet<Wallet<XpubDerivable, RgbDescr<XpubDerivable>>>, WalletError> {
        let stock = self.rgb_stock()?;
        self.rgb_wallet_from_stock(config, stock)
    }

    pub fn rgb_wallet_from_stock(
        &self,
        config: &Config,
        stock: SqliteStock,
    ) -> Result<SqliteRgbWallet<Wallet<XpubDerivable, RgbDescr<XpubDerivable>>>, WalletError> {
        let wallet = self.inner.bp_wallet::<RgbDescr<XpubDerivable>>(config)?;
        let wallet = SqliteRgbWallet::new(stock, wallet);

        Ok(wallet)
    }

    pub fn resolver(&self) -> Result<AnyResolver, WalletError> {
        let resolver =
            match (&self.resolver.esplora, &self.resolver.electrum, &self.resolver.mempool) {
                (None, Some(url), None) => AnyResolver::electrum_blocking(url, None),
                (Some(url), None, None) => AnyResolver::esplora_blocking(
                    esplora_blocking::esplora_client::Builder::new(url),
                ),
                (None, None, Some(url)) => AnyResolver::mempool_blocking(url, None),
                _ => Err(s!(" - error: no transaction resolver is specified; use either \
                             --esplora --mempool or --electrum argument")),
            }
            .map_err(WalletError::Resolver)?;
        resolver
            .check_chain_net(self.chain_net())
            .map_err(|e| WalletError::Resolver(e.to_string()))?;
        Ok(resolver)
    }

    /// The configured resolver, or `None` when no indexer was specified at all.
    ///
    /// For commands which can do without one: unlike [`Self::resolver`] an absent indexer
    /// is not an error, while one which is misconfigured (ambiguous, or serving another
    /// chain) still is.
    pub fn resolver_opt(&self) -> Result<Option<AnyResolver>, WalletError> {
        if self.resolver.esplora.is_none()
            && self.resolver.electrum.is_none()
            && self.resolver.mempool.is_none()
        {
            return Ok(None);
        }
        self.resolver().map(Some)
    }

    pub fn chain_net(&self) -> ChainNet {
        match self.general.network {
            Network::Mainnet => ChainNet::BitcoinMainnet,
            Network::Regtest => ChainNet::BitcoinRegtest,
            Network::Signet => ChainNet::BitcoinSignet,
            Network::Testnet3 => ChainNet::BitcoinTestnet3,
            Network::Testnet4 => ChainNet::BitcoinTestnet4,
        }
    }
}
