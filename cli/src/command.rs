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

use std::fs;
use std::fs::File;
use std::path::PathBuf;
use std::str::FromStr;

use amplify::confinement::{SmallOrdMap, U16 as MAX16};
use bpwallet::cli::{BpCommand, Config, Exec};
use bpwallet::psbt::{Output, PropKey, Psbt, PsbtConstructor, PsbtVer};
use bpwallet::{Derive, Sats};
use psrgbt::bp_conversion_utils::{
    address_payload_bitcoin_from_script_pubkey, network_bp_to_bitcoin, outpoint_bitcoin_to_bp,
    outpoint_bp_to_bitcoin,
};
use rgb::containers::{
    BuilderSeal, ConsignmentExt, ConsignmentVer, FileContent, TerminalSeals, Transfer,
    UncheckedContract, UncheckedTransfer, UniversalFile,
};
use rgb::indexers::ResolveSpvProof;
use rgb::invoice::{Beneficiary, Pay2Vout, RgbInvoice, RgbInvoiceBuilder, XChainNet};
use rgb::resolvers::ContractIssueResolver;
use rgb::schema::SchemaId;
use rgb::validation::{
    Failure, ResolveWitness, ValidationConfig, ValidationError, Validity, WitnessStatus,
};
use rgb::vm::WitnessOrd;
use rgb::{
    Allocation, BundleId, ContractId, GenesisSeal, GraphSeal, Identity, OpId, Outpoint, OutputSeal,
    OwnedFraction, SqliteRgbWallet, StateType, TokenIndex, TransferParams, Txid, WalletError,
    WalletProvider,
};
use rgbstd::contract::{AllocatedState, AssignmentsFilter, ContractData, ContractOp};
use rgbstd::persistence::sqlite::SqliteStock;
use rgbstd::persistence::ContractStateSnapshot;
use rgbstd::{KnownState, OutputAssignment};
use serde_crate::Serialize;
use strict_types::{FieldName, StrictVal};

use crate::args::BpWallet;
use crate::RgbArgs;

#[derive(Subcommand, Clone, PartialEq, Eq, Debug, Display)]
#[display(lowercase)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    #[clap(flatten)]
    #[display(inner)]
    General(bpwallet::cli::Command),

    /// Prints out list of known RGB schemata
    Schemata,

    /// Prints out list of known RGB contracts
    #[display("contracts")]
    Contracts,

    /// Imports RGB data into the store: schema definitions, consignments, etc
    #[display("import")]
    Import {
        /// Use BASE64 ASCII armoring for binary data
        #[arg(short)]
        armored: bool,

        /// File with RGB data
        ///
        /// If not provided, assumes `-a` and prints out data to STDOUT
        file: PathBuf,
    },

    /// Exports existing RGB contract
    #[display("export")]
    Export {
        /// Use BASE64 ASCII armoring for binary data
        #[arg(short)]
        armored: bool,

        /// Contract to export
        contract_id: ContractId,

        /// File with RGB data
        ///
        /// If not provided, assumes `-a` and reads the data from STDIN
        file: Option<PathBuf>,
    },

    /// Convert binary RGB file into a text armored version
    #[display("convert")]
    Armor {
        /// File with RGB data
        ///
        /// If not provided, assumes `-a` and reads the data from STDIN
        file: PathBuf,
    },

    /// Reports information about state of a contract
    #[display("state")]
    State {
        /// Show all state, including already spent and not owned by the wallet
        #[arg(short, long)]
        all: bool,

        /// Contract identifier
        contract_id: ContractId,
    },

    /// Print operation history for a contract
    #[display("history")]
    History {
        /// Print detailed information
        #[arg(long)]
        details: bool,

        /// Contract identifier
        contract_id: ContractId,
    },

    /// Display all known UTXOs belonging to this wallet
    Utxos,

    /// Issues new contract
    #[display("issue")]
    Issue {
        /// Issuer identity string
        issuer: Identity,

        /// File containing contract genesis description in YAML format
        contract_path: PathBuf,
    },

    /// Create new invoice
    #[display("invoice")]
    Invoice {
        /// Force address-based invoice
        #[arg(short, long)]
        address_based: bool,

        /// Assignment state name to use for the invoice
        ///
        /// If no state name is provided, it will be detected.
        #[arg(short, long)]
        assignment_name: Option<String>,

        /// Contract identifier
        contract_id: ContractId,

        /// Amount of tokens (in the smallest unit) to transfer
        #[arg(short, long)]
        amount: Option<u64>,

        /// Token index for NFT transfer
        #[arg(long)]
        token_index: Option<TokenIndex>,

        /// Fraction of an NFT token to transfer
        #[arg(long, requires = "token_index")]
        token_fraction: Option<OwnedFraction>,
    },

    /// Prepare PSBT file for transferring RGB assets
    ///
    /// In the most of cases you need to use `transfer` command instead of `prepare` and `consign`.
    #[display("prepare")]
    Prepare {
        /// Encode PSBT as V2
        #[clap(short = '2')]
        v2: bool,

        /// Amount of satoshis which should be paid to the address-based
        /// beneficiary
        #[arg(long, default_value = "2000")]
        sats: u64,

        /// Invoice data
        invoice: RgbInvoice,

        /// Fee
        fee: u64,

        /// Name of PSBT file to save. If not given, prints PSBT to STDOUT
        psbt: Option<PathBuf>,
    },

    /// Prepare consignment for transferring RGB assets
    ///
    /// In the most of the cases you need to use `transfer` command instead of `prepare` and
    /// `consign`.
    #[display("prepare")]
    Consign {
        /// Invoice data
        invoice: RgbInvoice,

        /// Name of PSBT file containing prepared transfer data
        psbt: PathBuf,

        /// File for generated transfer consignment
        consignment: PathBuf,
    },

    /// Transfer RGB assets
    #[display("transfer")]
    Transfer {
        /// Encode PSBT as V2
        #[arg(short = '2')]
        v2: bool,

        /// Amount of satoshis which should be paid to the address-based
        /// beneficiary
        #[arg(long, default_value = "2000")]
        sats: u64,

        /// Invoice data
        invoice: RgbInvoice,

        /// Fee for bitcoin transaction, in satoshis
        #[arg(short, long, default_value = "400")]
        fee: u64,

        /// File for generated transfer consignment
        consignment: PathBuf,

        /// Name of PSBT file to save. If not given, prints PSBT to STDOUT
        psbt: Option<PathBuf>,
    },

    /// Inspects any RGB data file
    #[display("inspect")]
    Inspect {
        /// RGB file to inspect
        file: PathBuf,

        /// Path to save the dumped data. If not given, prints PSBT to STDOUT.
        path: Option<PathBuf>,

        /// Export using directory format for the compound bundles
        #[clap(long, requires("path"))]
        dir: bool,
    },

    /// Reconstructs consignment from a YAML file
    #[display("reconstruct")]
    #[clap(hide = true)]
    Reconstruct {
        #[clap(long)]
        contract: bool,

        /// RGB file with the consignment YAML data
        src: PathBuf,

        /// Path for the resulting consignment file. If not given, prints the
        /// consignment to STDOUT.
        dst: Option<PathBuf>,
    },

    /// Validate transfer consignment
    #[display("validate")]
    Validate {
        /// File with the transfer consignment
        file: PathBuf,
    },

    /// Validate transfer consignment & accept to the store
    #[display("accept")]
    Accept {
        /// Accept the transfer even if some of its witness transactions are unknown to the
        /// indexer (e.g. not broadcast yet), taking them from the consignment
        #[arg(short, long)]
        force: bool,

        /// File with the transfer consignment
        file: PathBuf,
    },
}

impl Exec for RgbArgs {
    type Error = WalletError;
    const CONF_FILE_NAME: &'static str = "rgb.toml";

    fn exec(self, config: Config, _name: &'static str) -> Result<(), WalletError> {
        match &self.command {
            Command::General(cmd) => {
                self.inner.translate(cmd).exec(config, "rgb")?;
            }
            Command::Utxos => {
                self.inner
                    .translate(&BpCommand::Balance {
                        addr: true,
                        utxo: true,
                    })
                    .exec(config, "rgb")?;
            }

            Command::Schemata => {
                let stock = self.rgb_stock()?;
                for info in stock.schemata().map(|r| r.expect("store read")) {
                    print!("{info}");
                }
            }
            Command::Contracts => {
                let stock = self.rgb_stock()?;
                for info in stock.contracts().map(|r| r.expect("store read")) {
                    print!("{info}");
                }
            }

            Command::History {
                contract_id,
                details,
            } => {
                let wallet = self.rgb_wallet(&config)?;
                let mut history = wallet.history(*contract_id)?;
                history.sort_by_key(|op| op.witness.map(|w| w.ord).unwrap_or(WitnessOrd::Archived));
                if *details {
                    println!("Operation\tValue    \tState\t{:78}\tWitness", "Seal");
                } else {
                    println!("Operation\tValue    \t{:78}\tWitness", "Seal");
                }
                for ContractOp {
                    direction,
                    ty,
                    opids,
                    state,
                    to,
                    witness,
                } in history
                {
                    print!("{:9}\t", direction.to_string());
                    if let AllocatedState::Amount(amount) = state {
                        print!("{: >9}", amount.as_u64());
                    } else {
                        print!("{state:>9}");
                    }
                    if *details {
                        print!("\t{ty}");
                    }
                    println!(
                        "\t{}\t{}",
                        to.first().expect("at least one receiver is always present"),
                        witness
                            .map(|info| format!("{} ({})", info.id, info.ord))
                            .unwrap_or_else(|| s!("~"))
                    );
                    if *details {
                        println!(
                            "\topid={}",
                            opids
                                .iter()
                                .map(OpId::to_string)
                                .collect::<Vec<_>>()
                                .join("\n\topid=")
                        )
                    }
                }
            }

            Command::Import { armored, file } => {
                let mut stock = self.rgb_stock()?;
                assert!(!armored, "importing armored files is not yet supported");
                // TODO: Support armored files
                let content = UniversalFile::load_file(file)?;
                match content {
                    UniversalFile::SchemaDefinition(schema_def) => {
                        let schema_id = schema_def.schema_id();
                        eprintln!("Importing schema definition {schema_id}:");
                        eprintln!("- schema {} {schema_id:-}", schema_def.schema.name);
                        for lib in schema_def.libs.values() {
                            eprintln!("- type library {} {}", lib.name, lib.id());
                        }
                        for lib_id in schema_def.scripts.keys() {
                            eprintln!("- script library {lib_id}");
                        }
                        // Verified on import: the type system is rebuilt from the
                        // libraries above and checked against the ids the schema
                        // commits to.
                        stock.import_schema_definition(schema_def)?;
                        eprintln!("Schema definition is imported and verified");
                    }
                    UniversalFile::Contract(contract) => {
                        let id = contract.consignment_id();
                        eprintln!("Importing consignment {id}:");
                        let resolver = self.resolver()?;
                        eprint!("- validating the contract {} ... ", contract.contract_id());
                        let schema_rules = stock.schema_rules(contract.schema_id())?;
                        let validation_config = ValidationConfig {
                            chain_net: self.chain_net(),
                            ..Default::default()
                        };
                        let contract = contract
                            .validate(&schema_rules, &resolver, &validation_config)
                            .map_err(|status| {
                                eprintln!("failure");
                                status.to_string()
                            })?;
                        eprintln!("success");
                        stock.import_contract(contract, &resolver)?;
                        eprintln!("Consignment is imported");
                    }
                    UniversalFile::Transfer(_) => {
                        return Err(s!("use `validate` and `accept` commands to work with \
                                       transfer consignments")
                        .into());
                    }
                }
            }
            Command::Export {
                armored: _,
                contract_id,
                file,
            } => {
                let stock = self.rgb_stock()?;
                let contract = stock
                    .export_contract(*contract_id)
                    .map_err(|err| err.to_string())?;
                if let Some(file) = file {
                    // TODO: handle armored flag
                    contract.save_file(file)?;
                    eprintln!("Contract {contract_id} exported to '{}'", file.display());
                } else {
                    println!("{contract}");
                }
            }

            Command::Armor { file } => {
                let content = UniversalFile::load_file(file)?;
                println!("{content}");
            }

            Command::State { contract_id, all } => {
                let stock_path = self.general.base_dir();
                let stock = self.load_stock(stock_path.clone())?;

                enum StockOrWallet {
                    Stock(Box<SqliteStock>),
                    Wallet(Box<SqliteRgbWallet<BpWallet>>),
                }
                impl StockOrWallet {
                    fn stock(&self) -> &SqliteStock {
                        match self {
                            StockOrWallet::Stock(stock) => stock,
                            StockOrWallet::Wallet(wallet) => wallet.stock(),
                        }
                    }
                }

                let stock_wallet = match self.rgb_wallet_from_stock(&config, stock) {
                    Ok(wallet) => StockOrWallet::Wallet(Box::new(wallet)),
                    Err(_) => StockOrWallet::Stock(Box::new(self.load_stock(stock_path)?)),
                };

                let filter = match stock_wallet {
                    StockOrWallet::Wallet(ref wallet) if *all => Filter::WalletAll(wallet),
                    StockOrWallet::Wallet(ref wallet) => Filter::Wallet(wallet),
                    StockOrWallet::Stock(_) => {
                        println!("no wallets found");
                        Filter::NoWallet
                    }
                };

                let contract = stock_wallet.stock().contract_data(*contract_id)?;

                println!("\nGlobal:");
                for global_details in contract.rules.schema().global_types.values() {
                    let values = contract.global(global_details.name.clone());
                    for val in values {
                        println!("  {} := {}", global_details.name, val);
                    }
                }

                enum Filter<'w> {
                    Wallet(&'w SqliteRgbWallet<BpWallet>),
                    WalletAll(&'w SqliteRgbWallet<BpWallet>),
                    NoWallet,
                }
                impl AssignmentsFilter for Filter<'_> {
                    fn should_include(
                        &self,
                        outpoint: impl Into<Outpoint>,
                        id: Option<Txid>,
                    ) -> bool {
                        match self {
                            Filter::Wallet(wallet) => wallet
                                .wallet()
                                .filter_unspent()
                                .should_include(outpoint, id),
                            _ => true,
                        }
                    }
                }
                impl Filter<'_> {
                    fn comment(&self, outpoint: Outpoint) -> &'static str {
                        let outpoint = outpoint_bitcoin_to_bp(outpoint);
                        match self {
                            Filter::Wallet(rgb) if rgb.wallet().is_unspent(outpoint) => "",
                            Filter::WalletAll(rgb) if rgb.wallet().is_unspent(outpoint) => {
                                "-- unspent"
                            }
                            Filter::WalletAll(rgb) if rgb.wallet().has_outpoint(outpoint) => {
                                "-- spent"
                            }
                            _ => "-- third-party",
                        }
                    }
                }

                println!("\nOwned:");
                fn witness<S: KnownState>(
                    allocation: &OutputAssignment<S>,
                    contract: &ContractData<ContractStateSnapshot>,
                ) -> String {
                    allocation
                        .witness
                        .and_then(|w| match contract.witness_info(w) {
                            Ok(info) => info,
                            // the snapshot is already in memory, so the read
                            // this goes through cannot fail
                            Err(never) => match never {},
                        })
                        .map(|info| format!("{} ({})", info.id, info.ord))
                        .unwrap_or_else(|| s!("~"))
                }
                for details in contract.rules.schema().owned_types.values() {
                    println!("  State      \t{:78}\tWitness", "Seal");
                    println!("  {}:", details.name);
                    for allocation in contract.fungible(details.name.clone(), &filter) {
                        let allocation = allocation?;
                        println!(
                            "    {: >9}\t{}\t{} {}",
                            allocation.state.value(),
                            allocation.seal,
                            witness(&allocation, &contract),
                            filter.comment(allocation.seal.to_outpoint())
                        );
                    }
                    for allocation in contract.data(details.name.clone(), &filter) {
                        let allocation = allocation?;
                        println!(
                            "    {: >9}\t{}\t{} {}",
                            allocation.state,
                            allocation.seal,
                            witness(&allocation, &contract),
                            filter.comment(allocation.seal.to_outpoint())
                        );
                    }
                    for allocation in contract.rights(details.name.clone(), &filter) {
                        let allocation = allocation?;
                        println!(
                            "    {: >9}\t{}\t{} {}",
                            "right",
                            allocation.seal,
                            witness(&allocation, &contract),
                            filter.comment(allocation.seal.to_outpoint())
                        );
                    }
                }
            }
            Command::Issue {
                issuer,
                contract_path,
            } => {
                let mut stock = self.rgb_stock()?;

                let file = fs::File::open(contract_path)?;

                let code = serde_yaml::from_reader::<_, serde_yaml::Value>(file)?;

                let code = code
                    .as_mapping()
                    .expect("invalid YAML root-level structure");

                let schema_id_str = code
                    .get("schema")
                    .expect("must specify a schema")
                    .as_str()
                    .expect("schema must be a string");

                let schema_id = SchemaId::from_str(schema_id_str)?;
                let schema = stock.schema(schema_id)?;

                let mut builder =
                    stock.contract_builder(issuer.clone(), schema_id, self.chain_net())?;
                let types = builder.type_system().clone();
                if let Some(globals) = code.get("globals") {
                    for (name, val) in globals
                        .as_mapping()
                        .expect("invalid YAML: globals must be an mapping")
                    {
                        let name = name
                            .as_str()
                            .expect("invalid YAML: global name must be a string");
                        // Workaround for borrow checker:
                        let name = FieldName::try_from(name.to_owned()).expect("invalid type name");
                        let (type_id, global_details) = schema.global(name);
                        let sem_id = global_details.global_state_schema.sem_id;
                        let val = StrictVal::from(val.clone());
                        let typed_val = types
                            .typify(val, sem_id)
                            .expect("global type doesn't match type definition");

                        #[allow(deprecated)]
                        let serialized = types
                            .strict_serialize_type::<MAX16>(&typed_val)
                            .expect("internal error");
                        builder = builder
                            .add_global_state_raw(*type_id, serialized)
                            .expect("invalid global state data");
                    }
                }

                if let Some(assignments) = code.get("assignments") {
                    for (name, val) in assignments
                        .as_mapping()
                        .expect("invalid YAML: assignments must be an mapping")
                    {
                        let name = name
                            .as_str()
                            .expect("invalid YAML: assignments name must be a string");
                        // Workaround for borrow checker:
                        let name = FieldName::try_from(name.to_owned()).expect("invalid type name");
                        let (type_id, assignment_details) = schema.assignment(name);
                        let state_schema = assignment_details.owned_state_schema;

                        let assign = val.as_mapping().expect("an assignment must be a mapping");
                        let seal = assign
                            .get("seal")
                            .expect("assignment doesn't provide seal information")
                            .as_str()
                            .expect("seal must be a string");
                        let seal = OutputSeal::from_str(seal).expect("invalid seal definition");
                        let seal = GenesisSeal::new_random(seal.txid, seal.vout);

                        match state_schema.state_type() {
                            StateType::Void => todo!(),
                            StateType::Fungible => {
                                let amount = assign
                                    .get("amount")
                                    .expect("owned state must be a fungible amount")
                                    .as_u64()
                                    .expect("fungible state must be an integer");
                                let seal = BuilderSeal::Revealed(seal);
                                builder = builder
                                    .add_fungible_state_raw(*type_id, seal, amount)
                                    .expect("invalid global state data");
                            }
                            StateType::Structured => todo!(),
                        }
                    }
                }

                let contract = builder.issue_contract()?;
                let id = contract.contract_id();
                stock.import_contract(contract, &ContractIssueResolver)?;
                eprintln!(
                    "A new contract {id} is issued and added to the store.\nUse `export` command \
                     to export the contract."
                );
            }
            Command::Invoice {
                address_based,
                assignment_name,
                contract_id,
                amount,
                token_index,
                token_fraction,
            } => {
                let mut wallet = self.rgb_wallet(&config)?;

                let outpoint = wallet.wallet().coinselect(Sats::ZERO, |_| true).next();
                let network = wallet.wallet().network();
                let beneficiary = match (address_based, outpoint) {
                    (false, None) => {
                        return Err(WalletError::Custom(s!(
                            "blinded invoice requested but no suitable outpoint is available"
                        )));
                    }
                    (true, _) => {
                        let addr = wallet
                            .wallet()
                            .addresses(wallet.wallet().default_keychain())
                            .next()
                            .expect("no addresses left")
                            .addr;
                        let address_payload = address_payload_bitcoin_from_script_pubkey(
                            &addr.payload.script_pubkey(),
                        );
                        Beneficiary::WitnessVout(Pay2Vout::new(address_payload), None)
                    }
                    (_, Some(outpoint)) => {
                        let outpoint = outpoint_bp_to_bitcoin(outpoint);
                        let seal = GraphSeal::new_random(outpoint.txid, outpoint.vout);
                        wallet.stock_mut().store_secret_seal(seal)?;
                        Beneficiary::BlindedSeal(seal.to_secret_seal())
                    }
                };

                let network = network_bp_to_bitcoin(network);
                let mut builder = RgbInvoiceBuilder::new(XChainNet::bitcoin(network, beneficiary))
                    .set_contract(*contract_id);

                let state_type = match (amount, token_index.map(|i| (i, token_fraction))) {
                    (Some(amount), None) => {
                        builder = builder.set_amount_raw(*amount);
                        StateType::Fungible
                    }
                    (None, Some((index, fraction))) => {
                        builder = builder.set_allocation_raw(Allocation::with(
                            index,
                            fraction.unwrap_or(OwnedFraction::from(0)),
                        ));
                        StateType::Structured
                    }
                    _ => {
                        return Err(WalletError::Invoicing(s!(
                            "only amount or token data should be provided"
                        )))
                    }
                };

                let mut ass_name = assignment_name
                    .clone()
                    .map(FieldName::try_from)
                    .transpose()
                    .map_err(|e| {
                        WalletError::Invoicing(format!("invalid assignment name - {e}"))
                    })?;

                if let Ok(contract) = wallet.stock().contract_data(*contract_id) {
                    if let Some(ref assignment_name) = ass_name {
                        let (_, details) =
                            contract.rules.schema().assignment(assignment_name.clone());
                        if details.owned_state_schema.state_type() != state_type {
                            return Err(WalletError::Invoicing(s!(
                                "invalid assignment name for state type"
                            )));
                        }
                    } else {
                        let assignment_types = contract
                            .rules
                            .schema()
                            .assignment_types_for_state(state_type);
                        if assignment_types.len() == 1 {
                            ass_name = Some(
                                contract
                                    .rules
                                    .schema()
                                    .assignment_name(*assignment_types[0])
                                    .clone(),
                            );
                        } else {
                            return Err(WalletError::Invoicing(s!(
                                "cannot detect a default assignment type"
                            )));
                        }
                    }
                }

                if let Some(name) = ass_name {
                    builder = builder.set_assignment_name(name);
                }

                let invoice = builder.finish();
                println!("{invoice}");
            }
            Command::Prepare {
                v2,
                invoice,
                fee,
                sats,
                psbt: psbt_file,
            } => {
                let mut wallet = self.rgb_wallet(&config)?;
                // TODO: Support lock time and RBFs
                let params = TransferParams::with(*fee, *sats);

                let (psbt, _) = wallet
                    .construct_psbt::<PropKey, Output>(invoice, params)
                    .map_err(|err| err.to_string())?;

                let ver = if *v2 { PsbtVer::V2 } else { PsbtVer::V0 };
                match psbt_file {
                    Some(file_name) => {
                        let mut psbt_file = File::create(file_name)?;
                        psbt.encode(ver, &mut psbt_file)?;
                    }
                    None => match ver {
                        PsbtVer::V0 => println!("{psbt}"),
                        PsbtVer::V2 => println!("{psbt:#}"),
                    },
                }
            }
            Command::Consign {
                invoice,
                psbt: psbt_name,
                consignment: out_file,
            } => {
                let mut wallet = self.rgb_wallet(&config)?;
                let mut psbt_file = File::open(psbt_name)?;
                let mut psbt = Psbt::decode(&mut psbt_file)?;
                // the SPV proofs missing from the store are retrieved while composing, so
                // that the counterparty can verify the witnesses from block headers alone.
                // Composing with no indexer configured stays possible: the consignment then
                // carries just the proofs the store already has
                let spv_resolver = self.resolver_opt()?;
                let transfer = wallet
                    .transfer(
                        invoice,
                        &mut psbt,
                        None,
                        spv_resolver.as_ref().map(|r| r as &dyn ResolveSpvProof),
                    )
                    .map_err(|err| err.to_string())?;
                let mut psbt_file = File::create(psbt_name)?;
                psbt.encode(psbt.version, &mut psbt_file)?;
                transfer.save_file(out_file)?;
            }
            Command::Transfer {
                v2,
                invoice,
                fee,
                sats,
                psbt: psbt_file,
                consignment: out_file,
            } => {
                let mut wallet = self.rgb_wallet(&config)?;
                // TODO: Support lock time and RBFs
                let params = TransferParams::with(*fee, *sats);

                let spv_resolver = self.resolver_opt()?;
                let (mut psbt, _, transfer) = wallet
                    .pay::<PropKey, Output>(
                        invoice,
                        params,
                        spv_resolver.as_ref().map(|r| r as &dyn ResolveSpvProof),
                    )
                    .map_err(|err| err.to_string())?;

                transfer.save_file(out_file)?;

                psbt.version = if *v2 { PsbtVer::V2 } else { PsbtVer::V0 };
                match psbt_file {
                    Some(file_name) => {
                        let mut psbt_file = File::create(file_name)?;
                        psbt.encode(psbt.version, &mut psbt_file)?;
                    }
                    None => println!("{psbt}"),
                }
            }
            Command::Inspect { file, dir, path } => {
                #[derive(Clone, Debug, Serialize)]
                #[serde(crate = "serde_crate", rename_all = "camelCase")]
                pub struct ConsignmentInspection {
                    version: ConsignmentVer,
                    transfer: bool,
                    terminals: SmallOrdMap<BundleId, TerminalSeals>,
                }

                let content = UniversalFile::load_file(file)?;
                let consignment = match content {
                    UniversalFile::Contract(contract) if *dir => Some(contract),
                    UniversalFile::Transfer(transfer) if *dir => Some(transfer.into_contract()),
                    content => {
                        let s = serde_yaml::to_string(&content).expect("unable to present as YAML");
                        match path {
                            None => println!("{s}"),
                            Some(path) => fs::write(path, s)?,
                        }
                        None
                    }
                };
                if let Some(consignment) = consignment {
                    // Consignments no longer embed schema/types/scripts; those
                    // are distributed out-of-band via schema definitions.
                    let mut map = map![
                        s!("genesis.yaml") => serde_yaml::to_string(&consignment.genesis)?,
                        s!("bundles.yaml") => serde_yaml::to_string(&consignment.bundles)?,
                    ];
                    let contract = ConsignmentInspection {
                        version: consignment.version,
                        transfer: consignment.transfer,
                        terminals: consignment.terminals,
                    };
                    map.insert(s!("consignment-meta.yaml"), serde_yaml::to_string(&contract)?);
                    let path = path.as_ref().expect("required by clap");
                    fs::create_dir_all(path)?;
                    for (file, value) in map {
                        fs::write(format!("{}/{file}", path.display()), value)?;
                    }
                }
            }
            Command::Reconstruct {
                contract: false,
                src,
                dst,
            } => {
                let file = File::open(src)?;
                let transfer = serde_yaml::from_reader::<_, UncheckedTransfer>(&file)?
                    .into_checked()
                    .map_err(|err| err.to_string())?;
                match dst {
                    None => println!("{transfer}"),
                    Some(dst) => {
                        transfer.save_file(dst)?;
                    }
                }
            }
            Command::Reconstruct {
                contract: true,
                src,
                dst,
            } => {
                let file = File::open(src)?;
                let contract = serde_yaml::from_reader::<_, UncheckedContract>(&file)?
                    .into_checked()
                    .map_err(|err| err.to_string())?;
                match dst {
                    None => println!("{contract}"),
                    Some(dst) => {
                        contract.save_file(dst)?;
                    }
                }
            }
            Command::Validate { file } => {
                let stock = self.rgb_stock()?;
                let mut resolver = self.resolver()?;
                let consignment = Transfer::load_file(file)?;
                // the consignment is normally validated before its witness TXs get broadcast,
                // so the ones the indexer doesn't know are taken from the consignment, but
                // reported, since the transfer is valid only once they get broadcast and mined
                let mut unknown_witnesses = vec![];
                for witness_id in consignment.bundles.iter().map(|bw| bw.witness_id()) {
                    match resolver
                        .resolve_witness(witness_id)
                        .map_err(|e| WalletError::Resolver(e.to_string()))?
                    {
                        WitnessStatus::Resolved(_, ord) if ord != WitnessOrd::Archived => {}
                        _ => unknown_witnesses.push(witness_id),
                    }
                }
                resolver.add_consignment_txes(&consignment);
                let schema_rules = stock.schema_rules(consignment.schema_id())?;
                let validation_config = ValidationConfig {
                    chain_net: self.chain_net(),
                    ..Default::default()
                };
                let validated_consignment =
                    consignment.validate(&schema_rules, &resolver, &validation_config)?;
                let status = validated_consignment.validation_status();
                if status.validity() == Validity::Valid {
                    eprintln!("The provided consignment is valid")
                } else {
                    eprintln!("{status}");
                }
                if !unknown_witnesses.is_empty() {
                    eprintln!(
                        "Warning: these witness transactions are unknown to the indexer and were \
                         taken from the consignment, which is valid only once they get broadcast \
                         and mined:"
                    );
                    for witness_id in unknown_witnesses {
                        eprintln!("- {witness_id}");
                    }
                }
            }
            Command::Accept { force, file } => {
                let mut stock = self.rgb_stock()?;
                let mut resolver = self.resolver()?;
                let transfer = Transfer::load_file(file)?;
                if *force {
                    resolver.add_consignment_txes(&transfer);
                }
                let schema_rules = stock.schema_rules(transfer.schema_id())?;
                let validation_config = ValidationConfig {
                    chain_net: self.chain_net(),
                    ..Default::default()
                };
                let valid = transfer
                    .validate(&schema_rules, &resolver, &validation_config)
                    .map_err(|err| match err {
                        ValidationError::InvalidConsignment(Failure::SealNoPubWitness(
                            _,
                            witness_id,
                        )) => WalletError::Resolver(format!(
                            "witness transaction {witness_id} is unknown to the indexer; if it is \
                             not broadcast yet, use --force to take it from the consignment"
                        )),
                        err => err.into(),
                    })?;
                stock.accept_transfer(valid, &resolver)?;
                eprintln!("Transfer accepted into the store");
            }
        }
        Ok(())
    }
}
