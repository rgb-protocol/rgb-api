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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};

use amplify::Wrapper;
#[cfg(feature = "bp")]
use bpwallet::IdxBase;
use psrgbt::Terminal;
use rgbstd::bitcoin::key::UntweakedPublicKey;
use rgbstd::bitcoin::PublicKey;
use rgbstd::rgbcore::seals::txout::CloseMethod;
use rgbstd::tapret::TapretCommitment;

pub trait DescriptorRgb {
    fn close_method(&self) -> CloseMethod;
    fn add_tapret_tweak(&mut self, terminal: Terminal, tweak: TapretCommitment);
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TapretKey<K = UntweakedPublicKey> {
    pub tr: K,
    pub tweaks: BTreeMap<Terminal, BTreeSet<TapretCommitment>>,
}

impl<K: Display> Display for TapretKey<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "tapret({},tweaks(", self.tr)?;
        let mut iter = self.tweaks.iter().peekable();
        while let Some((term, tweaks)) = iter.next() {
            write!(f, "{}/{}=", term.keychain, term.index)?;
            let mut commitment_iter = tweaks.iter().peekable();
            while let Some(tweak) = commitment_iter.next() {
                write!(f, "{tweak}")?;
                if commitment_iter.peek().is_some() {
                    f.write_str(",")?;
                }
            }
            if iter.peek().is_some() {
                f.write_str(";")?;
            }
        }
        f.write_str("))")
    }
}

impl<K> TapretKey<K> {
    pub fn with_key(key: K) -> Self {
        TapretKey {
            tr: key,
            tweaks: empty!(),
        }
    }
}

impl<K> DescriptorRgb for TapretKey<K> {
    fn close_method(&self) -> CloseMethod { CloseMethod::TapretFirst }

    fn add_tapret_tweak(&mut self, terminal: Terminal, tweak: TapretCommitment) {
        self.tweaks.entry(terminal).or_default().insert(tweak);
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct WpkhDescr<K = PublicKey>(K);

impl<K: Display> Display for WpkhDescr<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { write!(f, "wpkh({})", self.0) }
}

impl<K> WpkhDescr<K> {
    pub fn with_key(key: K) -> Self { WpkhDescr(key) }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase",)
)]
#[non_exhaustive]
pub enum RgbDescr<K> {
    Wpkh(WpkhDescr<K>),
    TapretKey(TapretKey<K>),
}

impl<K> From<WpkhDescr<K>> for RgbDescr<K> {
    fn from(wpkh: WpkhDescr<K>) -> Self { RgbDescr::Wpkh(wpkh) }
}

impl<K> From<TapretKey<K>> for RgbDescr<K> {
    fn from(tapret: TapretKey<K>) -> Self { RgbDescr::TapretKey(tapret) }
}

impl<K: Display> Display for RgbDescr<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RgbDescr::Wpkh(wpkh) => Display::fmt(wpkh, f),
            RgbDescr::TapretKey(tapret_key) => Display::fmt(tapret_key, f),
        }
    }
}

impl<K> DescriptorRgb for RgbDescr<K> {
    fn close_method(&self) -> CloseMethod {
        match self {
            RgbDescr::Wpkh(_) => CloseMethod::OpretFirst,
            RgbDescr::TapretKey(d) => d.close_method(),
        }
    }

    fn add_tapret_tweak(&mut self, terminal: Terminal, tweak: TapretCommitment) {
        match self {
            RgbDescr::Wpkh(_) => panic!("adding tapret tweak to non-taproot descriptor"),
            RgbDescr::TapretKey(d) => d.add_tapret_tweak(terminal, tweak),
        }
    }
}

#[cfg(feature = "bp")]
pub mod bp_wallet_integration {
    use std::collections::{BTreeSet, HashMap};
    use std::iter;

    use bpwallet::{
        Derive, DeriveXOnly, DerivedScript, Descriptor, KeyOrigin, Keychain, LegacyKeySig,
        LegacyPk, NormalIndex, SigScript, SpkClass, TapDerivation, TapScript, TapTree,
        TaprootKeySig, TrKey, Witness, Wpkh, XOnlyPk, XpubAccount, XpubDerivable,
    };
    use indexmap::IndexMap;

    use super::*;

    impl<K> From<TrKey<K>> for TapretKey<K>
    where K: Clone + DeriveXOnly
    {
        fn from(tr_key: TrKey<K>) -> Self {
            let tr = tr_key
                .keys()
                .next()
                .cloned()
                .expect("TrKey should have a key");
            TapretKey {
                tr,
                tweaks: empty!(),
            }
        }
    }

    impl Descriptor<XpubDerivable> for RgbDescr<XpubDerivable> {
        fn class(&self) -> SpkClass {
            match self {
                RgbDescr::Wpkh(_) => SpkClass::P2wpkh,
                RgbDescr::TapretKey(_) => SpkClass::P2tr,
            }
        }

        fn keys<'a>(&'a self) -> impl Iterator<Item = &'a XpubDerivable>
        where XpubDerivable: 'a {
            match self {
                RgbDescr::Wpkh(wpkh) => {
                    vec![&wpkh.0]
                }
                RgbDescr::TapretKey(tapret_key) => {
                    vec![&tapret_key.tr]
                }
            }
            .into_iter()
        }

        fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
        where (): 'a {
            iter::empty()
        }

        fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> {
            match self {
                RgbDescr::Wpkh(d) => vec![d.0.spec()],
                RgbDescr::TapretKey(d) => vec![d.tr.spec()],
            }
            .into_iter()
        }

        fn legacy_keyset(&self, terminal: bpwallet::Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
            match self {
                RgbDescr::Wpkh(d) => Wpkh::from(d.0.clone()).legacy_keyset(terminal),
                RgbDescr::TapretKey(_) => IndexMap::new(),
            }
        }

        fn xonly_keyset(&self, terminal: bpwallet::Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
            match self {
                RgbDescr::Wpkh(_) => IndexMap::new(),
                RgbDescr::TapretKey(d) => TrKey::from(d.tr.clone()).xonly_keyset(terminal),
            }
        }

        fn legacy_witness(
            &self,
            keysigs: HashMap<&KeyOrigin, LegacyKeySig>,
        ) -> Option<(SigScript, Witness)> {
            match self {
                RgbDescr::Wpkh(d) => Wpkh::from(d.0.clone()).legacy_witness(keysigs),
                RgbDescr::TapretKey(_) => None,
            }
        }

        fn taproot_witness(&self, keysigs: HashMap<&KeyOrigin, TaprootKeySig>) -> Option<Witness> {
            match self {
                RgbDescr::Wpkh(_) => None,
                RgbDescr::TapretKey(d) => TrKey::from(d.tr.clone()).taproot_witness(keysigs),
            }
        }
    }

    impl Derive<DerivedScript> for RgbDescr<XpubDerivable> {
        fn default_keychain(&self) -> Keychain {
            match self {
                RgbDescr::Wpkh(d) => Wpkh::from(d.0.clone()).default_keychain(),
                RgbDescr::TapretKey(d) => TrKey::from(d.tr.clone()).default_keychain(),
            }
        }

        fn keychains(&self) -> BTreeSet<Keychain> {
            match self {
                RgbDescr::Wpkh(d) => Wpkh::from(d.0.clone()).keychains(),
                RgbDescr::TapretKey(d) => TrKey::from(d.tr.clone()).keychains(),
            }
        }

        fn derive(
            &self,
            keychain: impl Into<Keychain>,
            index: impl Into<NormalIndex>,
        ) -> impl Iterator<Item = DerivedScript> {
            let keychain = keychain.into();
            let index = index.into();

            // collecting as a workaround for different opaque types
            match self {
                RgbDescr::Wpkh(d) => Wpkh::from(d.0.clone()).derive(keychain, index).collect(),
                RgbDescr::TapretKey(d) => {
                    let derivation = &d.tr;
                    let terminal = Terminal::new(keychain.into_inner(), index.index());
                    let derived_keys =
                        <XpubDerivable as Derive<XOnlyPk>>::derive(derivation, keychain, index);
                    let mut derived_scripts = Vec::with_capacity(d.tweaks.len() + 1);
                    for internal_key in derived_keys {
                        derived_scripts.push(DerivedScript::TaprootKeyOnly(internal_key.into()));
                        for tweak in d.tweaks.get(&terminal).into_iter().flatten() {
                            let commitment = tweak.commit();
                            let tap_script = TapScript::from_unsafe(commitment.into_bytes());
                            let tap_tree = TapTree::with_single_leaf(tap_script);
                            let script =
                                DerivedScript::TaprootScript(internal_key.into(), tap_tree);
                            derived_scripts.push(script);
                        }
                    }
                    derived_scripts
                }
            }
            .into_iter()
        }
    }
}

#[cfg(feature = "bp")]
#[cfg(test)]
mod test {
    use std::str::FromStr;

    use bpwallet::{DeriveSet, Idx, Keychain, NormalIndex, Terminal, TrKey, XpubDerivable};
    use rgbstd::rgbcore::commit_verify::mpc::Commitment;
    use strict_types::StrictDumb;

    use super::*;
    use crate::DescriptorRgb;

    #[test]
    fn tapret_key_display() {
        let xpub_str = "[643a7adc/86h/1h/0h]tpubDCNiWHaiSkgnQjuhsg9kjwaUzaxQjUcmhagvYzqQ3TYJTgFGJstVaqnu4yhtFktBhCVFmBNLQ5sN53qKzZbMksm3XEyGJsEhQPfVZdWmTE2/<0;1>/*";
        let xpub = XpubDerivable::from_str(xpub_str).unwrap();
        let internal_key: TrKey<<XpubDerivable as DeriveSet>::XOnly> = TrKey::from(xpub.clone());

        // no tweaks
        let mut tapret_key = TapretKey::from(internal_key);
        assert_eq!(format!("{tapret_key}"), format!("tapret({xpub_str},tweaks())"));

        // add a tweak to a new terminal
        let terminal = Terminal::new(Keychain::INNER, NormalIndex::ZERO);
        let tweak = TapretCommitment::with(Commitment::strict_dumb(), 2);
        tapret_key.add_tapret_tweak(terminal.into(), tweak);
        assert_eq!(
            format!("{tapret_key}"),
            format!("tapret({xpub_str},tweaks(1/0=00000000000000000000000000000000000000000s))")
        );

        // add another tweak to a new terminal
        let terminal = Terminal::new(Keychain::from(7), NormalIndex::from(12u8));
        let tweak = TapretCommitment::with(Commitment::strict_dumb(), 5);
        tapret_key.add_tapret_tweak(terminal.into(), tweak.clone());
        assert_eq!(
            format!("{tapret_key}"),
            format!(
                "tapret({xpub_str},tweaks(1/0=00000000000000000000000000000000000000000s;7/\
                 12=00000000000000000000000000000000000000001p))"
            )
        );

        // add another tweak to an existing terminal
        let tweak = TapretCommitment::with(Commitment::strict_dumb(), 2);
        tapret_key.add_tapret_tweak(terminal.into(), tweak);
        assert_eq!(
            format!("{tapret_key}"),
            format!(
                "tapret({xpub_str},tweaks(1/0=00000000000000000000000000000000000000000s;7/\
                 12=00000000000000000000000000000000000000000s,\
                 00000000000000000000000000000000000000001p))"
            )
        );
    }
}
