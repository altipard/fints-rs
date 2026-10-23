//! FinTS 3.0 CLI Client
//!
//! A comprehensive command-line client for the FinTS 3.0 banking protocol.
//! Supports DKB and other FinTS-compatible German banks.
//!
//! # Usage
//!
//!   fints-client [global options] <subcommand> [options]
//!
//! # Example
//!
//!   fints-client --bank dkb setup
//!   fints-client --bank dkb sync
//!   fints-client --bank dkb transactions --from 2024-01-01

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use chrono::{NaiveDate, Utc};
use clap::{Args, Parser, Subcommand};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use fints::{
    all_banks, bank_by_blz, bank_ops_with_config,
    debug::{decode_message, format_decoded, format_wire_log, VerbosityLevel},
    error::FinTSError,
    flow::{Flow, SyncResult},
    protocol::{Dialog, PollResult},
    types::{
        AccountBalance, Blz, Bic, Iban, Pin, ProductId, SepaAccount, SecurityHolding,
        SystemId, TanMethod, Transaction, UserId,
    },
    workflow::FetchOpts,
    BankConfig, BankName, FinTSUrl,
};

// ═══════════════════════════════════════════════════════════════════════════════
// CLI Argument Definitions
// ═══════════════════════════════════════════════════════════════════════════════

/// FinTS 3.0 CLI Banking Client
#[derive(Parser, Debug)]
#[command(
    name = "fints-client",
    about = "FinTS 3.0 CLI banking client for German banks",
    version,
    long_about = "A comprehensive FinTS 3.0 (formerly HBCI) banking protocol client.\nSupports DKB and other German banks with TAN methods including pushTAN and chipTAN."
)]
struct Cli {
    /// Bank BLZ (e.g. "12030000" for DKB) or "custom"
    #[arg(long, global = true)]
    bank: Option<String>,

    /// Custom FinTS URL (with --bank custom)
    #[arg(long, global = true)]
    url: Option<String>,

    /// Bank code (BLZ)
    #[arg(long, global = true)]
    blz: Option<String>,

    /// FinTS user ID
    #[arg(long, global = true)]
    user: Option<String>,

    /// PIN (NOT RECOMMENDED — use interactive prompt)
    #[arg(long, global = true)]
    pin: Option<String>,

    /// Session name (default: bank ID)
    #[arg(long, global = true)]
    session: Option<String>,

    /// Override session directory [$FINTS_SESSION_DIR]
    #[arg(long, global = true)]
    session_dir: Option<PathBuf>,

    /// Don't save session to disk; print resume token instead
    #[arg(long, global = true)]
    no_persist: bool,

    /// Load session from a resume token
    #[arg(long, global = true)]
    resume_token: Option<String>,

    /// Verbose: show decoded segments
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Super verbose: show hex wire dumps
    #[arg(long, global = true)]
    debug_wire: bool,

    /// Output format: human (default), json, csv
    #[arg(long, default_value = "human", global = true)]
    output: OutputFormat,

    /// FinTS product ID [default: 4FC925A65CCF74BA0CCB1EAF5, env: FINTS_PRODUCT_ID]
    #[arg(long, global = true)]
    product_id: Option<String>,

    /// Provide TAN directly (for two-step flows)
    #[arg(long, global = true)]
    tan: Option<String>,

    /// Exit after TAN challenge (print state token)
    #[arg(long, global = true)]
    no_wait: bool,

    /// Max seconds to wait for decoupled TAN
    #[arg(long, default_value = "120", global = true)]
    poll_timeout: u64,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum OutputFormat {
    Human,
    Json,
    Csv,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Human => write!(f, "human"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Csv => write!(f, "csv"),
        }
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Interactive first-time setup and sync
    Setup,

    /// Full sync: balance + transactions + holdings
    Sync(SyncArgs),

    /// Fetch account balance
    Balance(BalanceArgs),

    /// Fetch account transactions
    Transactions(TransactionsArgs),

    /// Fetch securities/depot holdings
    Holdings(HoldingsArgs),

    /// Session management
    Sessions {
        #[command(subcommand)]
        action: SessionAction,
    },

    /// Inspect bank capabilities (sync + show BPD)
    Inspect,

    /// Decode a raw FinTS message from stdin
    Decode(DecodeArgs),

    /// Audit a FinTS server for protocol compliance
    Audit(AuditArgs),

    /// List known banks
    Banks,
}

#[derive(Args, Debug, Default)]
struct BalanceArgs {
    /// Account IBAN
    #[arg(long)]
    iban: Option<String>,

    /// Account BIC (optional if in session or discoverable from sync)
    #[arg(long)]
    bic: Option<String>,
}

#[derive(Args, Debug, Default)]
struct SyncArgs {
    /// Account IBAN (if not provided, uses first account from session)
    #[arg(long)]
    iban: Option<String>,

    /// Account BIC (optional if in session)
    #[arg(long)]
    bic: Option<String>,

    /// Days of transaction history to fetch [default: 90]
    #[arg(long, default_value = "90")]
    days: u32,

    /// Skip securities/depot holdings (faster, useful if no depot account)
    #[arg(long)]
    no_holdings: bool,

    /// Fetch all accounts from session (balance + transactions for each)
    #[arg(long)]
    all_accounts: bool,
}

#[derive(Args, Debug)]
struct TransactionsArgs {
    /// Start date (YYYY-MM-DD) [default: 90 days ago]
    #[arg(long)]
    from: Option<String>,

    /// End date (YYYY-MM-DD) [default: today]
    #[arg(long)]
    to: Option<String>,

    /// Account IBAN
    #[arg(long)]
    iban: Option<String>,

    /// Account BIC (optional if in session)
    #[arg(long)]
    bic: Option<String>,
}

#[derive(Args, Debug)]
struct HoldingsArgs {
    /// Account IBAN
    #[arg(long)]
    iban: Option<String>,

    /// Account BIC (optional if in session)
    #[arg(long)]
    bic: Option<String>,
}

#[derive(Subcommand, Debug)]
enum SessionAction {
    /// List saved sessions
    List,
    /// Show session details (BPD, TAN methods, accounts)
    Inspect {
        /// Session name
        name: String,
    },
    /// Delete a session
    Delete {
        /// Session name
        name: String,
    },
}

#[derive(Args, Debug)]
struct DecodeArgs {
    /// Input is hex encoded
    #[arg(long)]
    hex: bool,

    /// Input is base64 encoded
    #[arg(long)]
    b64: bool,

    /// Read from file instead of stdin
    #[arg(long)]
    file: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct AuditArgs {
    /// Bank code (BLZ)
    #[arg(long)]
    blz: Option<String>,

    /// FinTS URL
    #[arg(long)]
    url: Option<String>,

    /// User ID
    #[arg(long)]
    user: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Session File Format
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionFile {
    version: u32,
    bank_id: String,
    bank_url: String,
    blz: String,
    user_id: String,
    system_id: String,
    bpd_version: u16,
    upd_version: u16,
    tan_methods: Vec<TanMethodSer>,
    selected_security_function: String,
    accounts: Vec<SepaAccountSer>,
    #[serde(default)]
    operation_tan_required: HashMap<String, bool>,
    saved_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TanMethodSer {
    security_function: String,
    name: String,
    is_decoupled: bool,
    wait_before_first_poll: i32,
    wait_before_next_poll: i32,
    decoupled_max_polls: i32,
    hktan_version: u16,
    needs_tan_medium: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SepaAccountSer {
    iban: String,
    bic: String,
    account_number: String,
    blz: String,
    owner: Option<String>,
    product_name: Option<String>,
    currency: Option<String>,
}

impl From<&TanMethod> for TanMethodSer {
    fn from(m: &TanMethod) -> Self {
        TanMethodSer {
            security_function: m.security_function.as_str().to_string(),
            name: m.name.clone(),
            is_decoupled: m.is_decoupled,
            wait_before_first_poll: m.wait_before_first_poll,
            wait_before_next_poll: m.wait_before_next_poll,
            decoupled_max_polls: m.decoupled_max_polls,
            hktan_version: m.hktan_version,
            needs_tan_medium: m.needs_tan_medium,
        }
    }
}

impl From<&SepaAccount> for SepaAccountSer {
    fn from(a: &SepaAccount) -> Self {
        SepaAccountSer {
            iban: a.iban.as_str().to_string(),
            bic: a.bic.as_str().to_string(),
            account_number: a.account_number.clone(),
            blz: a.blz.as_str().to_string(),
            owner: a.owner.clone(),
            product_name: a.product_name.clone(),
            currency: a.currency.as_ref().map(|c| c.as_str().to_string()),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// IBAN Validation
// ═══════════════════════════════════════════════════════════════════════════════

/// Validate an IBAN without external crates.
///
/// Steps:
/// 1. Remove spaces, uppercase
/// 2. Check length (15-34 chars) and country code (2 alpha chars)
/// 3. Check mod-97: move first 4 chars to end, replace letters A=10..Z=35, mod 97 must be 1
/// 4. Validate German IBAN (DE): length must be 22
///
/// Returns `Ok(normalized_iban)` or `Err(reason)`.
fn validate_iban(iban: &str) -> Result<String, String> {
    // Step 1: Remove spaces and uppercase
    let iban: String = iban
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();

    // Step 2a: Check length (15-34 chars)
    if iban.len() < 15 || iban.len() > 34 {
        return Err(format!("Invalid length {} (must be 15–34 characters)", iban.len()));
    }

    // Step 2b: Check country code (first 2 chars must be alpha)
    let country_code = &iban[..2];
    if !country_code.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(format!("Invalid country code '{}' (must be 2 letters)", country_code));
    }

    // Step 2c: Check that positions 2–3 are digits (check digits)
    let check_digits = &iban[2..4];
    if !check_digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("Invalid check digits '{}' (must be 2 digits)", check_digits));
    }

    // Step 4: Validate German IBAN length
    if country_code == "DE" && iban.len() != 22 {
        return Err(format!(
            "German IBAN must be exactly 22 characters, got {}",
            iban.len()
        ));
    }

    // Step 3: Mod-97 check
    // Rearrange: move first 4 chars to end
    let rearranged = format!("{}{}", &iban[4..], &iban[..4]);

    // Replace each letter with its numeric value (A=10, B=11, ..., Z=35)
    let numeric: String = rearranged
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                (c as u32 - b'A' as u32 + 10).to_string()
            } else {
                c.to_string()
            }
        })
        .collect();

    // Compute mod 97 on the large integer by processing digit by digit
    let mut remainder: u64 = 0;
    for ch in numeric.chars() {
        let digit = ch.to_digit(10).unwrap_or(0) as u64;
        remainder = (remainder * 10 + digit) % 97;
    }

    if remainder != 1 {
        return Err(format!(
            "Check digit validation failed (mod-97 = {}, expected 1)",
            remainder
        ));
    }

    Ok(iban)
}

/// Format an IBAN for display with spaces every 4 characters.
/// Example: "DE89370400440532013000" → "DE89 3704 0044 0532 0130 00"
fn format_iban_display(iban: &str) -> String {
    let normalized: String = iban.chars().filter(|c| !c.is_whitespace()).collect();
    normalized
        .chars()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

// ═══════════════════════════════════════════════════════════════════════════════
// Session Management
// ═══════════════════════════════════════════════════════════════════════════════

fn get_session_dir(override_dir: Option<&PathBuf>) -> PathBuf {
    if let Some(d) = override_dir {
        return d.clone();
    }
    if let Ok(env_dir) = std::env::var("FINTS_SESSION_DIR") {
        return PathBuf::from(env_dir);
    }
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    home.join(".config").join("fints").join("sessions")
}

fn session_path(session_dir: &Path, name: &str) -> PathBuf {
    session_dir.join(format!("{}.json", name))
}

fn load_session(session_dir: &Path, name: &str) -> Result<SessionFile, String> {
    let path = session_path(session_dir, name);
    let data = std::fs::read_to_string(&path).map_err(|_| {
        format!(
            "No session found at {}. Run 'fints-client setup' first.",
            path.display()
        )
    })?;
    serde_json::from_str(&data).map_err(|e| format!("Failed to parse session file: {}", e))
}

fn save_session(
    session_dir: &Path,
    name: &str,
    session: &SessionFile,
) -> Result<(), String> {
    std::fs::create_dir_all(session_dir)
        .map_err(|e| format!("Failed to create session directory: {}", e))?;
    let path = session_path(session_dir, name);
    let json =
        serde_json::to_string_pretty(session).map_err(|e| format!("Serialization error: {}", e))?;
    std::fs::write(&path, json).map_err(|e| format!("Failed to write session file: {}", e))?;
    Ok(())
}

fn delete_session(session_dir: &Path, name: &str) -> Result<(), String> {
    let path = session_path(session_dir, name);
    std::fs::remove_file(&path)
        .map_err(|e| format!("Failed to delete session '{}': {}", name, e))
}

fn list_sessions(session_dir: &Path) -> Vec<(String, SessionFile)> {
    let mut sessions = Vec::new();
    let entries = match std::fs::read_dir(session_dir) {
        Ok(e) => e,
        Err(_) => return sessions,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if let Ok(data) = std::fs::read_to_string(&path) {
                    if let Ok(session) = serde_json::from_str::<SessionFile>(&data) {
                        sessions.push((stem.to_string(), session));
                    }
                }
            }
        }
    }
    sessions.sort_by(|a, b| a.0.cmp(&b.0));
    sessions
}

// ═══════════════════════════════════════════════════════════════════════════════
// Resume Token (base64-encoded zlib-compressed JSON)
// ═══════════════════════════════════════════════════════════════════════════════

fn encode_resume_token(session: &SessionFile) -> Result<String, String> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;

    let json =
        serde_json::to_vec(session).map_err(|e| format!("Serialization error: {}", e))?;

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&json)
        .map_err(|e| format!("Compression error: {}", e))?;
    let compressed = encoder
        .finish()
        .map_err(|e| format!("Compression finish error: {}", e))?;

    let encoded = base64::engine::general_purpose::STANDARD.encode(&compressed);
    Ok(format!("FINTS_TOKEN:{}", encoded))
}

fn decode_resume_token(token: &str) -> Result<SessionFile, String> {
    use flate2::read::ZlibDecoder;

    let token = token.trim();
    let b64_part = token
        .strip_prefix("FINTS_TOKEN:")
        .ok_or("Token must start with 'FINTS_TOKEN:'")?;

    let compressed = base64::engine::general_purpose::STANDARD
        .decode(b64_part)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    let mut decoder = ZlibDecoder::new(&compressed[..]);
    let mut json = Vec::new();
    decoder
        .read_to_end(&mut json)
        .map_err(|e| format!("Decompression error: {}", e))?;

    serde_json::from_slice(&json).map_err(|e| format!("JSON parse error: {}", e))
}

// ═══════════════════════════════════════════════════════════════════════════════
// PIN / TAN Input (always hidden via rpassword)
// ═══════════════════════════════════════════════════════════════════════════════

fn prompt_pin(cli_pin: Option<&str>) -> Result<String, String> {
    if let Some(pin) = cli_pin {
        eprintln!("Warning: providing PIN on command line is insecure");
        return Ok(pin.to_string());
    }
    rpassword::prompt_password("PIN: ").map_err(|e| format!("Failed to read PIN: {}", e))
}

fn prompt_tan(cli_tan: Option<&str>, challenge: Option<&str>) -> Result<String, String> {
    if let Some(tan) = cli_tan {
        return Ok(tan.to_string());
    }
    if let Some(c) = challenge {
        println!("TAN Challenge: {}", c);
    }
    rpassword::prompt_password("TAN: ").map_err(|e| format!("Failed to read TAN: {}", e))
}

/// TAN provider for the library: prints the bank's challenge text, then asks
/// for the TAN. `--tan` serves only the first TAN, every further order needs its own.
fn make_tan_provider(
    cli_tan: Option<String>,
) -> impl FnMut(&fints::protocol::TanChallenge) -> fints::error::Result<String> {
    let mut cli_tan = cli_tan;
    move |challenge| {
        let text = challenge.challenge.as_str();
        let text = if text.is_empty() { None } else { Some(text) };
        prompt_tan(cli_tan.take().as_deref(), text).map_err(FinTSError::Dialog)
    }
}

fn prompt_input(prompt_text: &str) -> Result<String, String> {
    print!("{}", prompt_text);
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("Read error: {}", e))?;
    Ok(input.trim().to_string())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Amount Formatting
// ═══════════════════════════════════════════════════════════════════════════════

/// Format a Decimal with 2 decimal places and thousands separator (e.g. 1,234.56).
fn format_amount(amount: &Decimal) -> String {
    let formatted = format!("{:.2}", amount);
    let (integer_part, decimal_part) = formatted
        .split_once('.')
        .unwrap_or((&formatted, "00"));

    let is_negative = integer_part.starts_with('-');
    let digits = if is_negative {
        &integer_part[1..]
    } else {
        integer_part
    };

    let with_commas: String = digits
        .chars()
        .rev()
        .enumerate()
        .flat_map(|(i, c)| {
            if i > 0 && i % 3 == 0 {
                vec![',', c]
            } else {
                vec![c]
            }
        })
        .collect::<String>()
        .chars()
        .rev()
        .collect();

    if is_negative {
        format!("-{}.{}", with_commas, decimal_part)
    } else {
        format!("{}.{}", with_commas, decimal_part)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Bank Resolution
// ═══════════════════════════════════════════════════════════════════════════════

struct ResolvedBank {
    /// BLZ used as the canonical bank identifier.
    blz: String,
    name: String,
    url: String,
    /// Full BankConfig for use with bank_ops_with_config (when not in registry)
    config: BankConfig,
}

impl ResolvedBank {
    fn to_bank_ops(&self) -> fints::AnyBank {
        // If it's a known registry bank use the typed implementation, otherwise generic
        match fints::bank_ops(&self.blz) {
            Ok(bank) => bank,
            Err(_) => bank_ops_with_config(self.config.clone()),
        }
    }
}

fn resolve_bank(cli: &Cli) -> Result<ResolvedBank, String> {
    // Explicit custom URL takes priority
    if let Some(url) = &cli.url {
        let blz = cli.blz.clone()
            .or_else(|| cli.bank.clone())
            .unwrap_or_default();
        let name = bank_by_blz(&blz)
            .map(|b| b.name.as_str().to_string())
            .unwrap_or_else(|| "Custom".to_string());
        let config = BankConfig::new(
            name.clone(), blz.clone(),
            "", // BIC not required for custom banks
            url.clone(),
        );
        return Ok(ResolvedBank { blz, name, url: url.clone(), config });
    }

    // --bank accepts a BLZ
    if let Some(blz) = &cli.bank {
        if let Some(config) = bank_by_blz(blz) {
            return Ok(ResolvedBank {
                blz: config.blz.as_str().to_string(),
                name: config.name.as_str().to_string(),
                url: config.url.as_str().to_string(),
                config: config.clone(),
            });
        }
        return Err(format!(
            "Unknown BLZ '{}'. Use --blz <blz> or --url <url>. See 'banks' subcommand for a list.",
            blz
        ));
    }

    if let Some(blz) = &cli.blz {
        if let Some(config) = bank_by_blz(blz) {
            return Ok(ResolvedBank {
                blz: config.blz.as_str().to_string(),
                name: config.name.as_str().to_string(),
                url: config.url.as_str().to_string(),
                config: config.clone(),
            });
        }
        return Err(format!(
            "Unknown BLZ '{}'. Use --url <url> for a custom endpoint.",
            blz
        ));
    }

    Err("No bank specified. Use --bank <blz>, --blz <blz>, or --url <url>".to_string())
}

fn get_product_id(cli: &Cli) -> ProductId {
    let id = cli
        .product_id
        .clone()
        .or_else(|| std::env::var("FINTS_PRODUCT_ID").ok())
        .unwrap_or_else(|| "4FC925A65CCF74BA0CCB1EAF5".to_string());
    ProductId::new(id)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Decoupled TAN polling loop
// ═══════════════════════════════════════════════════════════════════════════════

async fn poll_decoupled_tan(
    dialog: fints::protocol::Dialog<fints::protocol::TanPending>,
    task_reference: &fints::types::TaskReference,
    first_wait: u64,
    next_wait: u64,
    max_polls: u32,
) -> fints::error::Result<fints::protocol::Dialog<fints::protocol::Open>> {
    tokio::time::sleep(Duration::from_secs(first_wait)).await;

    let mut dlg = dialog;
    let mut polls = 0u32;

    loop {
        polls += 1;
        if max_polls > 0 && polls > max_polls {
            return Err(FinTSError::TanTimeout);
        }

        match dlg.poll(task_reference).await? {
            PollResult::Confirmed(open, _response) => {
                println!(" confirmed!");
                return Ok(open);
            }
            PollResult::Pending(d) => {
                print!(".");
                io::stdout().flush().ok();
                tokio::time::sleep(Duration::from_secs(next_wait)).await;
                dlg = d;
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Output Formatting
// ═══════════════════════════════════════════════════════════════════════════════

fn print_balance_human(iban: &str, balance: &AccountBalance, account_name: Option<&str>) {
    let display = format_iban_display(iban);
    let acct_part = account_name
        .map(|n| format!(" ({})", n))
        .unwrap_or_default();
    println!("Account: {}{}", display, acct_part);
    println!(
        "Balance: {} {} (as of {})",
        format_amount(&balance.amount),
        balance.currency,
        balance.date
    );
    if let Some(avail) = &balance.available {
        println!("Available: {} {}", format_amount(avail), balance.currency);
    }
    if let Some(credit) = &balance.credit_line {
        println!("Credit line: {} {}", format_amount(credit), balance.currency);
    }
}

fn print_transactions_human(transactions: &[Transaction]) {
    println!("\nTransactions ({}):", transactions.len());
    for tx in transactions {
        let sign = if tx.amount >= Decimal::ZERO { "+" } else { "" };
        let party = tx
            .applicant_name
            .as_deref()
            .or(tx.purpose.as_deref())
            .unwrap_or("—");
        println!(
            "  {}  {}{} {}  {}",
            tx.date,
            sign,
            format_amount(&tx.amount),
            tx.currency,
            &party[..party.len().min(45)]
        );
    }
}

fn print_holdings_human(holdings: &[SecurityHolding]) {
    if holdings.is_empty() {
        return;
    }
    // Compute total portfolio value for summary
    let total_eur: Option<rust_decimal::Decimal> = holdings.iter()
        .filter_map(|h| {
            h.market_value.as_ref().and_then(|v| {
                // Only sum EUR-denominated for simplicity
                if h.market_value_currency.as_ref().map(|c| c.as_str()) == Some("EUR") {
                    Some(*v)
                } else {
                    None
                }
            })
        })
        .reduce(|a, b| a + b);

    println!("\nSecurities / Depot ({} positions):", holdings.len());
    println!(
        "  {:<32}  {:<14}  {:>8}  {:>16}  {:>16}",
        "Name", "ISIN", "Units", "Price", "Value"
    );
    println!("  {}", "─".repeat(90));
    for h in holdings {
        let isin_str = h.isin.as_ref().map(|i| i.as_str()).unwrap_or("—");
        let wkn_str = h.wkn.as_ref().map(|w| w.as_str()).unwrap_or("");
        let price_str = match (&h.price, &h.price_currency) {
            (Some(p), Some(c)) => format!("{} {}", format_amount(p), c),
            (Some(p), None) => format_amount(p),
            _ => "—".to_string(),
        };
        let value_str = match (&h.market_value, &h.market_value_currency) {
            (Some(v), Some(c)) => format!("{} {}", format_amount(v), c),
            (Some(v), None) => format_amount(v),
            _ => "—".to_string(),
        };
        let profit_str = match &h.profit_loss {
            Some(pl) if *pl >= rust_decimal::Decimal::ZERO => format!("  +{}", format_amount(pl)),
            Some(pl) => format!("  {}", format_amount(pl)),
            None => String::new(),
        };
        let date_str = h.price_date.map(|d| format!(" ({})", d)).unwrap_or_default();
        let name = &h.name[..h.name.len().min(32)];
        println!(
            "  {:<32}  {:<14}  {:>8}  {:>16}  {:>16}{}",
            name,
            if wkn_str.is_empty() { isin_str.to_string() } else { format!("{} / {}", isin_str, wkn_str) },
            format_amount(&h.quantity),
            format!("{}{}", price_str, date_str),
            value_str,
            profit_str
        );
    }
    if let Some(total) = total_eur {
        println!("  {}", "─".repeat(90));
        println!("  {:<32}  {:<14}  {:>8}  {:>16}  {:>16}",
            "Total (EUR positions)", "", "", "", format!("{} EUR", format_amount(&total)));
    }
}

/// Print holdings as a JSON array
fn print_holdings_json(holdings: &[SecurityHolding]) {
    println!("{}", serde_json::to_string_pretty(holdings).unwrap_or_default());
}

/// Print holdings as CSV
fn print_holdings_csv(holdings: &[SecurityHolding]) {
    let mut wtr = csv::Writer::from_writer(io::stdout());
    let _ = wtr.write_record(["name", "isin", "wkn", "quantity", "price", "price_currency", "price_date", "market_value", "market_value_currency", "profit_loss"]);
    for h in holdings {
        let _ = wtr.write_record([
            h.name.as_str(),
            h.isin.as_ref().map(|i| i.as_str()).unwrap_or(""),
            h.wkn.as_ref().map(|w| w.as_str()).unwrap_or(""),
            &h.quantity.to_string(),
            h.price.as_ref().map(|p| p.to_string()).as_deref().unwrap_or(""),
            h.price_currency.as_ref().map(|c| c.as_str()).unwrap_or(""),
            h.price_date.map(|d| d.to_string()).as_deref().unwrap_or(""),
            h.market_value.as_ref().map(|v| v.to_string()).as_deref().unwrap_or(""),
            h.market_value_currency.as_ref().map(|c| c.as_str()).unwrap_or(""),
            h.profit_loss.as_ref().map(|p| p.to_string()).as_deref().unwrap_or(""),
        ]);
    }
    let _ = wtr.flush();
}

fn print_sync_result_human(result: &SyncResult) {
    println!("\nAccount: {}", format_iban_display(result.iban.as_str()));
    if !result.bic.as_str().is_empty() {
        println!("BIC:     {}", result.bic);
    }
    if let Some(bal) = &result.balance {
        if let Some(ref avail) = bal.available {
            println!(
                "Balance: {} {} (available: {} {}; as of {})",
                format_amount(&bal.amount), bal.currency,
                format_amount(avail), bal.currency,
                bal.date
            );
        } else {
            println!(
                "Balance: {} {} (as of {})",
                format_amount(&bal.amount),
                bal.currency,
                bal.date
            );
        }
        if let (Some(pending), Some(pdate)) = (&bal.pending_amount, bal.pending_date) {
            println!("Pending: {} {} (as of {})", format_amount(pending), bal.currency, pdate);
        }
    }
    if result.transactions.is_empty() && result.holdings.is_empty() {
        println!("(no transaction or holdings data)");
    } else {
        print_transactions_human(&result.transactions);
        print_holdings_human(&result.holdings);
    }
}

fn print_sync_result_json(result: &SyncResult) {
    let json = serde_json::json!({
        "iban": result.iban.as_str(),
        "bic": result.bic.as_str(),
        "balance": result.balance,
        "transactions": result.transactions,
        "holdings": result.holdings,
        "system_id": result.system_id.as_ref().map(|s| s.as_str()),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&json).unwrap_or_default()
    );
}

fn print_sync_result_csv(result: &SyncResult) {
    let mut wtr = csv::Writer::from_writer(io::stdout());
    let _ = wtr.write_record(["date", "amount", "currency", "applicant", "purpose"]);
    for tx in &result.transactions {
        let _ = wtr.write_record([
            tx.date.to_string().as_str(),
            tx.amount.to_string().as_str(),
            tx.currency.as_str(),
            tx.applicant_name.as_deref().unwrap_or(""),
            tx.purpose.as_deref().unwrap_or(""),
        ]);
    }
    let _ = wtr.flush();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Error Mapping
// ═══════════════════════════════════════════════════════════════════════════════

fn map_fints_error(e: &FinTSError) -> String {
    match e {
        FinTSError::PinWrong => "Authentication failed: PIN incorrect.".to_string(),
        FinTSError::AccountLocked => "Account locked. Contact your bank.".to_string(),
        FinTSError::Transport(msg) => format!("Connection failed: {}", msg),
        FinTSError::TanTimeout => {
            "TAN timeout: user did not confirm within the allowed time.".to_string()
        }
        FinTSError::Reqwest(e) => format!("Connection failed: {}", e),
        _ => e.to_string(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Subcommand: banks
// ═══════════════════════════════════════════════════════════════════════════════

async fn cmd_banks() {
    let banks = all_banks();
    println!("Known banks ({} total):", banks.len());
    println!(
        "{:<12} {:<14} {:<40} {}",
        "BLZ", "BIC", "Name", "URL"
    );
    println!("{}", "-".repeat(100));
    for bank in &banks {
        let name = bank.name.as_str();
        // Truncate at a char boundary to avoid panicking on multi-byte chars
        let name_trunc: String = name.chars().take(40).collect();
        println!(
            "{:<12} {:<14} {:<40} {}",
            bank.blz.as_str(),
            bank.bic.as_str(),
            name_trunc,
            bank.url.as_str(),
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Subcommand: setup
// ═══════════════════════════════════════════════════════════════════════════════

async fn cmd_setup(cli: &Cli) -> Result<(), String> {
    println!("=== FinTS First-Time Setup ===\n");

    // Bank selection — prompt interactively if not on command line
    let bank = match resolve_bank(cli) {
        Ok(b) => b,
        Err(_) => {
            println!("Available banks:");
            for (i, bank) in all_banks().iter().enumerate() {
                println!("  {}. {} (BLZ: {})", i + 1, bank.name.as_str(), bank.blz.as_str());
            }
            let banks = all_banks();
            println!("  {}. Custom URL", banks.len() + 1);

            let choice = prompt_input(&format!("Bank [1]: "))?;
            let idx: usize = if choice.is_empty() {
                1
            } else {
                choice.parse().unwrap_or(1)
            };

            if idx > 0 && idx <= banks.len() {
                let b = &banks[idx - 1];
                ResolvedBank {
                    blz: b.blz.as_str().to_string(),
                    name: b.name.as_str().to_string(),
                    url: b.url.as_str().to_string(),
                    config: b.clone(),
                }
            } else {
                let url = prompt_input("FinTS URL: ")?;
                let blz = prompt_input("BLZ: ")?;
                let config = BankConfig::new("Custom", blz.clone(), "", url.clone());
                ResolvedBank {
                    blz: blz.clone(),
                    name: "Custom".to_string(),
                    url,
                    config,
                }
            }
        }
    };

    // Credentials
    let user_id_str = if let Some(u) = &cli.user {
        u.clone()
    } else {
        prompt_input("User ID: ")?
    };
    let pin_str = prompt_pin(cli.pin.as_deref())?;

    let user_id = UserId::new(&user_id_str);
    let pin = Pin::new(&pin_str);
    let product_id = get_product_id(cli);

    println!("\nConnecting to {} ({})...", bank.name, bank.url);

    let (mut flow, challenge) = Flow::initiate_with_bank(
        bank.to_bank_ops(),
        &user_id,
        &pin,
        &product_id,
        None,
        None,
        None,
    )
    .await
    .map_err(|e| map_fints_error(&e))?;

    // Banks that demand a TAN at dialog start: answer it now (decoupled ones are polled in sync).
    if !challenge.no_tan_required && !challenge.decoupled {
        let mut provider = make_tan_provider(cli.tan.clone());
        flow.confirm_tan_with(&mut provider)
            .await
            .map_err(|e| map_fints_error(&e))?;
        flow.end().await.ok();
    }

    let system_id = flow.system_id().clone();

    println!(
        "Connected. System ID: {}",
        if system_id.is_assigned() {
            system_id.as_str().to_string()
        } else {
            "unassigned".to_string()
        }
    );

    if !challenge.no_tan_required {
        println!(
            "Note: {} TAN methods available.",
            challenge.tan_methods.len()
        );
        println!(
            "Use 'sync' or 'transactions' to fetch data (TAN will be requested then)."
        );
    }

    // Build session
    let session = SessionFile {
        version: 1,
        bank_id: bank.blz.clone(),
        bank_url: bank.url.clone(),
        blz: bank.blz.clone(),
        user_id: user_id_str.clone(),
        system_id: system_id.as_str().to_string(),
        bpd_version: 0,
        upd_version: 0,
        tan_methods: challenge.tan_methods.iter().map(TanMethodSer::from).collect(),
        selected_security_function: challenge
            .allowed_security_functions
            .first()
            .map(|s| s.as_str().to_string())
            .unwrap_or_else(|| "999".to_string()),
        accounts: Vec::new(),
        operation_tan_required: HashMap::new(),
        saved_at: Utc::now().to_rfc3339(),
    };

    let session_name = cli
        .session
        .clone()
        .unwrap_or_else(|| bank.blz.clone());

    if cli.no_persist {
        let token = encode_resume_token(&session)?;
        println!("\nResume token (use with --resume-token):");
        println!("{}", token);
    } else {
        let session_dir = get_session_dir(cli.session_dir.as_ref());
        save_session(&session_dir, &session_name, &session)?;
        println!(
            "\nSession saved to {}",
            session_path(&session_dir, &session_name).display()
        );
    }

    println!(
        "\nSetup complete! Use 'fints-client --bank {} sync' to fetch your account data.",
        bank.blz
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Subcommand: sync
// ═══════════════════════════════════════════════════════════════════════════════

async fn cmd_sync(cli: &Cli, sync_args: &SyncArgs) -> Result<(), String> {
    let bank = resolve_bank(cli)?;
    let session_name = cli
        .session
        .clone()
        .unwrap_or_else(|| bank.blz.clone());
    let session_dir = get_session_dir(cli.session_dir.as_ref());

    let existing_session = if let Some(token) = &cli.resume_token {
        Some(decode_resume_token(token)?)
    } else {
        load_session(&session_dir, &session_name).ok()
    };

    let user_id_str = cli
        .user
        .clone()
        .or_else(|| existing_session.as_ref().map(|s| s.user_id.clone()))
        .ok_or("No user ID. Use --user or run 'fints-client setup' first.")?;

    let pin_str = prompt_pin(cli.pin.as_deref())?;

    let user_id = UserId::new(&user_id_str);
    let pin = Pin::new(&pin_str);
    let product_id = get_product_id(cli);

    let system_id = existing_session
        .as_ref()
        .map(|s| SystemId::new(&s.system_id));

    println!("Initiating connection to {}...", bank.url);

    let (mut flow, challenge) = Flow::initiate_with_bank(
        bank.to_bank_ops(),
        &user_id,
        &pin,
        &product_id,
        system_id.as_ref(),
        None,
        None,
    )
    .await
    .map_err(|e| map_fints_error(&e))?;

    println!("Connected. System ID: {}", flow.system_id());

    // Resolve accounts
    let accounts = existing_session
        .as_ref()
        .map(|s| s.accounts.clone())
        .unwrap_or_default();

    let days = sync_args.days;
    let fetch_opts = if sync_args.no_holdings {
        FetchOpts::no_holdings(days)
    } else {
        FetchOpts::all(days)
    };

    // Determine which accounts to fetch
    let target_accounts: Vec<(String, String)> = if sync_args.all_accounts && !accounts.is_empty() {
        // All accounts from session
        accounts.iter().map(|a| (a.iban.clone(), a.bic.clone())).collect()
    } else if let Some(ref explicit_iban) = sync_args.iban {
        let iban = validate_iban(explicit_iban).map_err(|e| format!("Invalid IBAN: {}", e))?;
        let bic = sync_args.bic.clone()
            .or_else(|| accounts.iter().find(|a| a.iban == iban).map(|a| a.bic.clone()))
            .unwrap_or_default();
        vec![(iban, bic)]
    } else if let Some(acc) = accounts.first() {
        vec![(acc.iban.clone(), acc.bic.clone())]
    } else {
        let iban = prompt_input("Account IBAN: ")?;
        let iban = validate_iban(&iban).map_err(|e| format!("Invalid IBAN: {}", e))?;
        let bic = prompt_input("Account BIC: ")?;
        vec![(iban, bic)]
    };

    // Fetch first account via confirm_and_fetch_opts (handles TAN polling)
    let (first_iban, first_bic) = target_accounts.first()
        .cloned()
        .ok_or("No account to sync")?;

    let mut tan_provider = make_tan_provider(cli.tan.clone());
    let result = flow
        .confirm_and_fetch_opts_with_tan(&first_iban, &first_bic, &fetch_opts, &mut tan_provider)
        .await
        .map_err(|e| map_fints_error(&e))?;

    // Update session
    let system_id_str = result
        .system_id
        .as_ref()
        .map(|s| s.as_str().to_string())
        .unwrap_or_else(|| flow.system_id().as_str().to_string());

    let updated_session = SessionFile {
        version: 1,
        bank_id: bank.blz.clone(),
        bank_url: bank.url.clone(),
        blz: bank.blz.clone(),
        user_id: user_id_str.clone(),
        system_id: system_id_str,
        bpd_version: existing_session
            .as_ref()
            .map(|s| s.bpd_version)
            .unwrap_or(0),
        upd_version: existing_session
            .as_ref()
            .map(|s| s.upd_version)
            .unwrap_or(0),
        tan_methods: challenge.tan_methods.iter().map(TanMethodSer::from).collect(),
        selected_security_function: existing_session
            .as_ref()
            .map(|s| s.selected_security_function.clone())
            .unwrap_or_else(|| "999".to_string()),
        accounts: accounts.clone(),
        operation_tan_required: HashMap::new(),
        saved_at: Utc::now().to_rfc3339(),
    };

    if cli.no_persist {
        let token = encode_resume_token(&updated_session)?;
        println!("\nResume token:");
        println!("{}", token);
    } else {
        save_session(&session_dir, &session_name, &updated_session)
            .map_err(|e| format!("Failed to save session: {}", e))?;
    }

    match cli.output {
        OutputFormat::Human => print_sync_result_human(&result),
        OutputFormat::Json => print_sync_result_json(&result),
        OutputFormat::Csv => print_sync_result_csv(&result),
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Subcommand: balance
// ═══════════════════════════════════════════════════════════════════════════════

async fn cmd_balance(cli: &Cli, balance_args: &BalanceArgs) -> Result<(), String> {
    let bank = resolve_bank(cli)?;
    let session_name = cli
        .session
        .clone()
        .unwrap_or_else(|| bank.blz.clone());
    let session_dir = get_session_dir(cli.session_dir.as_ref());

    let existing_session = load_session(&session_dir, &session_name).ok();

    let user_id_str = cli
        .user
        .clone()
        .or_else(|| existing_session.as_ref().map(|s| s.user_id.clone()))
        .ok_or("No user ID. Use --user or run 'fints-client setup' first.")?;

    let pin_str = prompt_pin(cli.pin.as_deref())?;
    let user_id = UserId::new(&user_id_str);
    let pin = Pin::new(&pin_str);
    let product_id = get_product_id(cli);
    let system_id = existing_session
        .as_ref()
        .map(|s| SystemId::new(&s.system_id));

    let (mut flow, _challenge) = Flow::initiate_with_bank(
        bank.to_bank_ops(),
        &user_id,
        &pin,
        &product_id,
        system_id.as_ref(),
        None,
        None,
    )
    .await
    .map_err(|e| map_fints_error(&e))?;

    let accounts = existing_session
        .as_ref()
        .map(|s| s.accounts.clone())
        .unwrap_or_default();

    let (iban, bic) = if let Some(ref explicit_iban) = balance_args.iban {
        let iban = validate_iban(explicit_iban).map_err(|e| format!("Invalid IBAN: {}", e))?;
        let bic = balance_args.bic.clone()
            .or_else(|| accounts.iter().find(|a| a.iban == iban).map(|a| a.bic.clone()))
            .unwrap_or_default();
        (iban, bic)
    } else if let Some(acc) = accounts.first() {
        (acc.iban.clone(), acc.bic.clone())
    } else {
        let iban = prompt_input("Account IBAN: ")?;
        let iban =
            validate_iban(&iban).map_err(|e| format!("Invalid IBAN: {}", e))?;
        let bic = prompt_input("Account BIC: ")?;
        (iban, bic)
    };

    // Fetch only 1 day to get balance quickly
    let mut tan_provider = make_tan_provider(cli.tan.clone());
    let result = flow
        .confirm_and_fetch_opts_with_tan(&iban, &bic, &FetchOpts::all(1), &mut tan_provider)
        .await
        .map_err(|e| map_fints_error(&e))?;

    if let Some(balance) = &result.balance {
        match cli.output {
            OutputFormat::Human => {
                let product_name = existing_session
                    .as_ref()
                    .and_then(|s| s.accounts.first())
                    .and_then(|a| a.product_name.as_deref());
                print_balance_human(&iban, balance, product_name);
            }
            OutputFormat::Json => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(balance).unwrap_or_default()
                );
            }
            OutputFormat::Csv => {
                println!("date,amount,currency");
                println!(
                    "{},{},{}",
                    balance.date, balance.amount, balance.currency
                );
            }
        }
    } else {
        println!("No balance data returned.");
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Subcommand: transactions
// ═══════════════════════════════════════════════════════════════════════════════

async fn cmd_transactions(cli: &Cli, args: &TransactionsArgs) -> Result<(), String> {
    let bank = resolve_bank(cli)?;
    let session_name = cli
        .session
        .clone()
        .unwrap_or_else(|| bank.blz.clone());
    let session_dir = get_session_dir(cli.session_dir.as_ref());

    let existing_session = load_session(&session_dir, &session_name).ok();

    let user_id_str = cli
        .user
        .clone()
        .or_else(|| existing_session.as_ref().map(|s| s.user_id.clone()))
        .ok_or("No user ID. Use --user or run 'fints-client setup' first.")?;

    let pin_str = prompt_pin(cli.pin.as_deref())?;
    let user_id = UserId::new(&user_id_str);
    let pin = Pin::new(&pin_str);
    let product_id = get_product_id(cli);
    let system_id = existing_session
        .as_ref()
        .map(|s| SystemId::new(&s.system_id));

    let today = Utc::now().date_naive();
    let default_from = today - chrono::Duration::days(90);

    let from_date = args
        .from
        .as_deref()
        .map(|s| {
            NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|_| {
                format!("Invalid date '{}', expected YYYY-MM-DD", s)
            })
        })
        .transpose()?
        .unwrap_or(default_from);

    let to_date = args
        .to
        .as_deref()
        .map(|s| {
            NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|_| {
                format!("Invalid date '{}', expected YYYY-MM-DD", s)
            })
        })
        .transpose()?
        .unwrap_or(today);

    let days = (to_date - from_date).num_days().max(1) as u32;

    let (iban, bic) = resolve_iban_bic_from_args(
        args.iban.as_deref(),
        args.bic.as_deref(),
        existing_session.as_ref(),
    )?;

    let (mut flow, _challenge) = Flow::initiate_with_bank(
        bank.to_bank_ops(),
        &user_id,
        &pin,
        &product_id,
        system_id.as_ref(),
        None,
        None,
    )
    .await
    .map_err(|e| map_fints_error(&e))?;

    let mut tan_provider = make_tan_provider(cli.tan.clone());
    let result = flow
        .confirm_and_fetch_opts_with_tan(&iban, &bic, &FetchOpts::all(days), &mut tan_provider)
        .await
        .map_err(|e| map_fints_error(&e))?;

    match cli.output {
        OutputFormat::Human => {
            println!("Account: {}", format_iban_display(&iban));
            println!("Period: {} to {}", from_date, to_date);
            print_transactions_human(&result.transactions);
        }
        OutputFormat::Json => {
            let json = serde_json::json!({
                "iban": iban,
                "from": from_date.to_string(),
                "to": to_date.to_string(),
                "transactions": result.transactions,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&json).unwrap_or_default()
            );
        }
        OutputFormat::Csv => {
            let mut wtr = csv::Writer::from_writer(io::stdout());
            let _ = wtr.write_record([
                "date",
                "valuta_date",
                "amount",
                "currency",
                "applicant",
                "applicant_iban",
                "purpose",
                "posting_text",
                "status",
            ]);
            for tx in &result.transactions {
                let _ = wtr.write_record([
                    tx.date.to_string().as_str(),
                    tx.valuta_date
                        .map(|d| d.to_string())
                        .as_deref()
                        .unwrap_or(""),
                    tx.amount.to_string().as_str(),
                    tx.currency.as_str(),
                    tx.applicant_name.as_deref().unwrap_or(""),
                    tx.applicant_iban
                        .as_ref()
                        .map(|i| i.as_str())
                        .unwrap_or(""),
                    tx.purpose.as_deref().unwrap_or(""),
                    tx.posting_text.as_deref().unwrap_or(""),
                    &format!("{:?}", tx.status),
                ]);
            }
            let _ = wtr.flush();
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Subcommand: holdings
// ═══════════════════════════════════════════════════════════════════════════════

async fn cmd_holdings(cli: &Cli, args: &HoldingsArgs) -> Result<(), String> {
    let bank = resolve_bank(cli)?;
    let session_name = cli
        .session
        .clone()
        .unwrap_or_else(|| bank.blz.clone());
    let session_dir = get_session_dir(cli.session_dir.as_ref());

    let existing_session = load_session(&session_dir, &session_name).ok();

    let user_id_str = cli
        .user
        .clone()
        .or_else(|| existing_session.as_ref().map(|s| s.user_id.clone()))
        .ok_or("No user ID. Use --user or run 'fints-client setup' first.")?;

    let pin_str = prompt_pin(cli.pin.as_deref())?;
    let user_id = UserId::new(&user_id_str);
    let pin = Pin::new(&pin_str);
    let product_id = get_product_id(cli);
    let system_id = existing_session
        .as_ref()
        .map(|s| SystemId::new(&s.system_id));

    let (iban, bic) = resolve_iban_bic_from_args(
        args.iban.as_deref(),
        args.bic.as_deref(),
        existing_session.as_ref(),
    )?;

    let (mut flow, _challenge) = Flow::initiate_with_bank(
        bank.to_bank_ops(),
        &user_id,
        &pin,
        &product_id,
        system_id.as_ref(),
        None,
        None,
    )
    .await
    .map_err(|e| map_fints_error(&e))?;

    // Use confirm_and_fetch_opts with holdings-only fetch for efficiency
    let result = flow
        .confirm_and_fetch_opts(&iban, &bic, &FetchOpts { balance: false, transactions: false, holdings: true, days: 0 })
        .await
        .map_err(|e| map_fints_error(&e))?;
    let holdings = result.holdings;

    println!("Account: {}", format_iban_display(&iban));
    match cli.output {
        OutputFormat::Human => print_holdings_human(&holdings),
        OutputFormat::Json => print_holdings_json(&holdings),
        OutputFormat::Csv => print_holdings_csv(&holdings),
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Subcommand: sessions
// ═══════════════════════════════════════════════════════════════════════════════

async fn cmd_sessions_list(cli: &Cli) {
    let session_dir = get_session_dir(cli.session_dir.as_ref());
    let sessions = list_sessions(&session_dir);

    if sessions.is_empty() {
        println!("No sessions found in {}", session_dir.display());
        println!("Run 'fints-client setup' to create one.");
        return;
    }

    println!("Sessions in {}:", session_dir.display());
    println!(
        "{:<15} {:<15} {:<20} {:<22} {:<12}",
        "Name", "Bank", "User", "Saved", "System ID"
    );
    println!("{}", "-".repeat(87));

    for (name, session) in sessions {
        let saved = &session.saved_at[..session.saved_at.len().min(19)];
        let sys_id_status = if session.system_id != "0" && !session.system_id.is_empty() {
            "assigned"
        } else {
            "unassigned"
        };
        println!(
            "{:<15} {:<15} {:<20} {:<22} {}",
            name, session.bank_id, session.user_id, saved, sys_id_status
        );
    }
}

async fn cmd_sessions_inspect(cli: &Cli, name: &str) -> Result<(), String> {
    let session_dir = get_session_dir(cli.session_dir.as_ref());
    let session = load_session(&session_dir, name)?;

    println!("Session: {}", name);
    println!("Bank ID:   {}", session.bank_id);
    println!("URL:       {}", session.bank_url);
    println!("BLZ:       {}", session.blz);
    println!("User:      {}", session.user_id);
    let sys_display = if session.system_id.len() > 20 {
        &session.system_id[..20]
    } else {
        &session.system_id
    };
    println!(
        "System ID: {} ({})",
        sys_display,
        if session.system_id != "0" { "assigned" } else { "unassigned" }
    );
    println!(
        "BPD v{}  UPD v{}",
        session.bpd_version, session.upd_version
    );
    println!("Saved: {}", session.saved_at);

    println!("\nTAN methods ({}):", session.tan_methods.len());
    for m in &session.tan_methods {
        let method_type = if m.is_decoupled {
            format!(
                "[decoupled, poll every {}s, max {} polls]",
                m.wait_before_next_poll, m.decoupled_max_polls
            )
        } else {
            "[two-step]".to_string()
        };
        println!(
            "  #{}  {:<25} {}",
            m.security_function, m.name, method_type
        );
    }

    if !session.operation_tan_required.is_empty() {
        println!("\nHIPINS (operation TAN requirements):");
        let mut ops: Vec<_> = session.operation_tan_required.iter().collect();
        ops.sort_by_key(|(k, _)| k.as_str());
        for (op, required) in ops {
            println!(
                "  {}: {}",
                op,
                if *required { "TAN required" } else { "no TAN required" }
            );
        }
    }

    if !session.accounts.is_empty() {
        println!("\nAccounts ({}):", session.accounts.len());
        for acc in &session.accounts {
            let product = acc.product_name.as_deref().unwrap_or("—");
            let currency = acc.currency.as_deref().unwrap_or("EUR");
            println!(
                "  {} ({} {})",
                format_iban_display(&acc.iban),
                product,
                currency
            );
        }
    }

    Ok(())
}

async fn cmd_sessions_delete(cli: &Cli, name: &str) -> Result<(), String> {
    let session_dir = get_session_dir(cli.session_dir.as_ref());
    delete_session(&session_dir, name)?;
    println!("Session '{}' deleted.", name);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Subcommand: inspect
// ═══════════════════════════════════════════════════════════════════════════════

async fn cmd_inspect(cli: &Cli) -> Result<(), String> {
    let bank = resolve_bank(cli)?;

    let user_id_str = cli
        .user
        .clone()
        .ok_or("No user ID. Use --user <id>")?;
    let pin_str = prompt_pin(cli.pin.as_deref())?;

    let user_id = UserId::new(&user_id_str);
    let pin = Pin::new(&pin_str);
    let product_id = get_product_id(cli);

    println!("Connecting to {} ({})...", bank.name, bank.url);

    let blz = Blz::new(&bank.blz);

    let dialog = Dialog::new(&bank.url, &blz, &user_id, &pin, &product_id)
        .map_err(|e| format!("Dialog error: {}", e))?;

    let (synced, _resp) = dialog
        .sync()
        .await
        .map_err(|e| map_fints_error(&e))?;

    let (params, system_id) = synced
        .end()
        .await
        .map_err(|e| map_fints_error(&e))?;

    println!();
    println!("BLZ:        {}", bank.blz);
    println!("Bank:       {}", bank.name);
    println!("URL:        {}", bank.url);
    println!("User:       {}", user_id_str);
    println!(
        "System ID:  {} ({})",
        {
            let s = system_id.as_str();
            if s.len() > 24 { &s[..24] } else { s }
        },
        if system_id.is_assigned() { "assigned" } else { "unassigned" }
    );

    println!("\nBPD version: {}", params.bpd_version);

    let bpd_segs: Vec<String> = params
        .bpd_segments
        .iter()
        .map(|s| format!("{}(v{})", s.segment_type(), s.segment_version()))
        .collect();
    if !bpd_segs.is_empty() {
        println!("Segments: {}", bpd_segs.join(", "));
    }

    println!("\nTAN methods ({}):", params.tan_methods.len());
    for m in &params.tan_methods {
        let method_type = if m.is_decoupled {
            format!(
                "[decoupled, poll every {}s, max {} polls]",
                m.wait_before_next_poll, m.decoupled_max_polls
            )
        } else {
            "[two-step]".to_string()
        };
        println!("  #{}  {:<25} {}", m.security_function, m.name, method_type);
    }

    if !params.operation_tan_required.is_empty() {
        println!("\nHIPINS (operation TAN requirements):");
        let mut ops: Vec<_> = params.operation_tan_required.iter().collect();
        ops.sort_by_key(|(k, _)| k.as_str());
        for (op, required) in ops {
            println!(
                "  {}: {}",
                op,
                if *required { "TAN required" } else { "no TAN required" }
            );
        }
    }

    if !params.accounts_from_upd.is_empty() {
        println!("\nAccounts ({}):", params.accounts_from_upd.len());
        for acc in &params.accounts_from_upd {
            let product = acc.product_name.as_deref().unwrap_or("—");
            let currency = acc.currency.as_ref().map(|c| c.as_str()).unwrap_or("EUR");
            match validate_iban(acc.iban.as_str()) {
                Ok(_) => println!(
                    "  {} ({} {})",
                    format_iban_display(acc.iban.as_str()),
                    product,
                    currency
                ),
                Err(e) => println!(
                    "  {} [IBAN invalid: {}] ({} {})",
                    acc.iban, e, product, currency
                ),
            }
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Subcommand: decode
// ═══════════════════════════════════════════════════════════════════════════════

async fn cmd_decode(cli: &Cli, args: &DecodeArgs) -> Result<(), String> {
    let raw_bytes: Vec<u8> = if let Some(file) = &args.file {
        std::fs::read(file)
            .map_err(|e| format!("Failed to read '{}': {}", file.display(), e))?
    } else {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| format!("Failed to read stdin: {}", e))?;
        buf
    };

    let data: Vec<u8> = if args.hex {
        let hex_str = String::from_utf8_lossy(&raw_bytes);
        let hex_str: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();
        (0..hex_str.len())
            .step_by(2)
            .filter(|&i| i + 1 < hex_str.len())
            .map(|i| {
                u8::from_str_radix(&hex_str[i..i + 2], 16)
                    .map_err(|e| format!("Invalid hex at position {}: {}", i, e))
            })
            .collect::<Result<Vec<u8>, String>>()?
    } else if args.b64 {
        let b64_str = String::from_utf8_lossy(&raw_bytes);
        let b64_str: String = b64_str.chars().filter(|c| !c.is_whitespace()).collect();
        base64::engine::general_purpose::STANDARD
            .decode(&b64_str)
            .map_err(|e| format!("Base64 decode error: {}", e))?
    } else {
        // Auto-detect: if all printable base64 chars and not starting with FinTS segment type
        let text = String::from_utf8_lossy(&raw_bytes);
        let trimmed: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        let looks_like_b64 = trimmed.len() > 0
            && trimmed
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
            && !trimmed.starts_with("HNHBK")
            && !trimmed.starts_with("HN");
        if looks_like_b64 {
            base64::engine::general_purpose::STANDARD
                .decode(&trimmed)
                .unwrap_or(raw_bytes)
        } else {
            raw_bytes
        }
    };

    let verbosity = if cli.debug_wire {
        VerbosityLevel::Full
    } else if cli.verbose {
        VerbosityLevel::Segments
    } else {
        VerbosityLevel::Minimal
    };

    if cli.debug_wire {
        println!(
            "{}",
            format_wire_log("DECODED MESSAGE", &data, VerbosityLevel::Full)
        );
    } else {
        match decode_message(&data) {
            Ok(msg) => println!("{}", format_decoded(&msg, verbosity)),
            Err(e) => return Err(format!("Decode error: {}", e)),
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Subcommand: audit
// ═══════════════════════════════════════════════════════════════════════════════

async fn cmd_audit(cli: &Cli, args: &AuditArgs) -> Result<(), String> {
    let blz_str = args
        .blz
        .clone()
        .or_else(|| cli.blz.clone())
        .ok_or("No BLZ specified. Use audit --blz <blz> or global --blz")?;

    let url_str = args
        .url
        .clone()
        .or_else(|| cli.url.clone())
        .or_else(|| bank_by_blz(&blz_str).map(|b| b.url.as_str().to_string()))
        .ok_or("No URL. Use audit --url <url> or --bank <id>")?;

    let user_id_str = args
        .user
        .clone()
        .or_else(|| cli.user.clone())
        .ok_or("No user ID. Use audit --user or global --user")?;

    let pin_str = prompt_pin(cli.pin.as_deref())?;

    println!("Auditing {}...", url_str);

    let blz = Blz::new(&blz_str);
    let user_id = UserId::new(&user_id_str);
    let pin = Pin::new(&pin_str);
    let product_id = get_product_id(cli);

    // Sync dialog
    print!("  Sync dialog:          ");
    let _ = io::stdout().flush();
    let dialog = Dialog::new(&url_str, &blz, &user_id, &pin, &product_id)
        .map_err(|e| format!("Dialog creation failed: {}", e))?;

    match dialog.sync().await {
        Ok((synced, _resp)) => {
            println!("OK");

            let (params, system_id) = synced.end().await.map_err(|e| map_fints_error(&e))?;

            print!("  System ID:            ");
            println!(
                "{}",
                if system_id.is_assigned() {
                    "OK (assigned)"
                } else {
                    "OK (unassigned)"
                }
            );

            print!("  BPD presence:         ");
            println!(
                "{}",
                if params.bpd_version > 0 {
                    format!("OK (v{})", params.bpd_version)
                } else {
                    "WARN: no BPD version found".to_string()
                }
            );

            print!("  TAN methods:          ");
            println!(
                "{}",
                if !params.tan_methods.is_empty() {
                    format!("OK ({} methods)", params.tan_methods.len())
                } else {
                    "WARN: no TAN methods".to_string()
                }
            );

            let has_decoupled = params.tan_methods.iter().any(|m| m.is_decoupled);
            let decoupled_ok = params
                .tan_methods
                .iter()
                .filter(|m| m.is_decoupled)
                .all(|m| m.wait_before_first_poll > 0 && m.wait_before_next_poll > 0);

            print!("  HITANS format:        ");
            if has_decoupled && !decoupled_ok {
                println!("WARN: decoupled TAN methods missing poll timing params");
            } else {
                println!("OK");
            }

            let total_warnings = usize::from(params.tan_methods.is_empty())
                + usize::from(params.bpd_version == 0)
                + usize::from(has_decoupled && !decoupled_ok);

            println!("\n  Total: 0 errors, {} warnings", total_warnings);
        }
        Err(e) => {
            println!("FAIL: {}", map_fints_error(&e));
            println!("\n  Total: 1 error, 0 warnings");
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helper: Resolve IBAN/BIC from args or session
// ═══════════════════════════════════════════════════════════════════════════════

fn resolve_iban_from_args(
    iban_arg: Option<&str>,
    session: Option<&SessionFile>,
) -> Result<(String, String), String> {
    resolve_iban_bic_from_args(iban_arg, None, session)
}

fn resolve_iban_bic_from_args(
    iban_arg: Option<&str>,
    bic_arg: Option<&str>,
    session: Option<&SessionFile>,
) -> Result<(String, String), String> {
    if let Some(iban_raw) = iban_arg {
        let iban = validate_iban(iban_raw).map_err(|e| format!("Invalid IBAN: {}", e))?;
        let bic = bic_arg.map(|s| s.to_string())
            .or_else(|| session
                .and_then(|s| s.accounts.iter().find(|a| a.iban == iban))
                .map(|a| a.bic.clone()))
            .unwrap_or_default();
        let bic = if bic.is_empty() {
            prompt_input("Account BIC: ")?
        } else {
            bic
        };
        return Ok((iban, bic));
    }

    if let Some(s) = session {
        if let Some(acc) = s.accounts.first() {
            return Ok((acc.iban.clone(), acc.bic.clone()));
        }
    }

    let iban = prompt_input("Account IBAN: ")?;
    let iban = validate_iban(&iban).map_err(|e| format!("Invalid IBAN: {}", e))?;
    let bic = bic_arg.map(|s| s.to_string()).or_else(|| {
        prompt_input("Account BIC: ").ok()
    }).unwrap_or_default();
    Ok((iban, bic))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing with appropriate verbosity
    let env_filter = if cli.debug_wire {
        "fints=debug"
    } else if cli.verbose {
        "fints=info"
    } else {
        "fints=warn"
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(env_filter)),
        )
        .with_writer(io::stderr)
        .init();

    let result = run(&cli).await;

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn run(cli: &Cli) -> Result<(), String> {
    match &cli.command {
        Command::Banks => {
            cmd_banks().await;
            Ok(())
        }
        Command::Setup => cmd_setup(cli).await,
        Command::Sync(args) => cmd_sync(cli, args).await,
        Command::Balance(args) => cmd_balance(cli, args).await,
        Command::Transactions(args) => cmd_transactions(cli, args).await,
        Command::Holdings(args) => cmd_holdings(cli, args).await,
        Command::Sessions { action } => match action {
            SessionAction::List => {
                cmd_sessions_list(cli).await;
                Ok(())
            }
            SessionAction::Inspect { name } => cmd_sessions_inspect(cli, name).await,
            SessionAction::Delete { name } => cmd_sessions_delete(cli, name).await,
        },
        Command::Inspect => cmd_inspect(cli).await,
        Command::Decode(args) => cmd_decode(cli, args).await,
        Command::Audit(args) => cmd_audit(cli, args).await,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── IBAN validation ─────────────────────────────────────────────────────

    #[test]
    fn test_validate_iban_valid_de() {
        let result = validate_iban("DE89 3704 0044 0532 0130 00");
        assert!(result.is_ok(), "Expected valid IBAN, got: {:?}", result);
        assert_eq!(result.unwrap(), "DE89370400440532013000");
    }

    #[test]
    fn test_validate_iban_too_short() {
        let result = validate_iban("DE123");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("length"));
    }

    #[test]
    fn test_validate_iban_invalid_country_code() {
        let result = validate_iban("12 3704 0044 0532 0130 00");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_iban_wrong_de_length() {
        // DE IBANs must be exactly 22 chars
        let result = validate_iban("DE8937040044053201300011");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("22"));
    }

    #[test]
    fn test_validate_iban_bad_checksum() {
        // Same as valid but check digits changed to 00
        let result = validate_iban("DE00370400440532013000");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_iban_nl() {
        // Dutch IBAN — 18 chars
        let result = validate_iban("NL91ABNA0417164300");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_iban_gb() {
        // UK IBAN — 22 chars
        let result = validate_iban("GB29NWBK60161331926819");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_iban_strips_spaces() {
        let spaced = validate_iban("DE89 3704 0044 0532 0130 00").unwrap();
        let nospace = validate_iban("DE89370400440532013000").unwrap();
        assert_eq!(spaced, nospace);
    }

    // ── IBAN display ────────────────────────────────────────────────────────

    #[test]
    fn test_format_iban_display() {
        assert_eq!(
            format_iban_display("DE89370400440532013000"),
            "DE89 3704 0044 0532 0130 00"
        );
    }

    #[test]
    fn test_format_iban_display_strips_spaces() {
        assert_eq!(
            format_iban_display("DE89 3704 0044 0532 0130 00"),
            "DE89 3704 0044 0532 0130 00"
        );
    }

    // ── Amount formatting ────────────────────────────────────────────────────

    #[test]
    fn test_format_amount_positive() {
        let amount = Decimal::from(1234);
        assert_eq!(format_amount(&amount), "1,234.00");
    }

    #[test]
    fn test_format_amount_negative() {
        let amount = Decimal::from(-42);
        assert_eq!(format_amount(&amount), "-42.00");
    }

    #[test]
    fn test_format_amount_large() {
        let amount: Decimal = "1234567.89".parse().unwrap();
        assert_eq!(format_amount(&amount), "1,234,567.89");
    }

    #[test]
    fn test_format_amount_zero() {
        assert_eq!(format_amount(&Decimal::ZERO), "0.00");
    }

    #[test]
    fn test_format_amount_small() {
        let amount: Decimal = "0.50".parse().unwrap();
        assert_eq!(format_amount(&amount), "0.50");
    }

    // ── Resume token roundtrip ───────────────────────────────────────────────

    #[test]
    fn test_resume_token_roundtrip() {
        let session = SessionFile {
            version: 1,
            bank_id: "12030000".to_string(),
            bank_url: "https://fints.dkb.de/fints".to_string(),
            blz: "12030000".to_string(),
            user_id: "testuser".to_string(),
            system_id: "abc123".to_string(),
            bpd_version: 78,
            upd_version: 3,
            tan_methods: Vec::new(),
            selected_security_function: "912".to_string(),
            accounts: Vec::new(),
            operation_tan_required: HashMap::new(),
            saved_at: "2024-01-01T12:00:00Z".to_string(),
        };

        let token = encode_resume_token(&session).unwrap();
        assert!(token.starts_with("FINTS_TOKEN:"));

        let decoded = decode_resume_token(&token).unwrap();
        assert_eq!(decoded.bank_id, "12030000");
        assert_eq!(decoded.user_id, "testuser");
        assert_eq!(decoded.system_id, "abc123");
        assert_eq!(decoded.bpd_version, 78);
    }

    #[test]
    fn test_resume_token_rejects_invalid() {
        let result = decode_resume_token("NOT_A_TOKEN");
        assert!(result.is_err());
    }

    // ── Session file path ────────────────────────────────────────────────────

    #[test]
    fn test_session_path() {
        let dir = PathBuf::from("/tmp/sessions");
        let path = session_path(&dir, "dkb");
        assert_eq!(path, PathBuf::from("/tmp/sessions/dkb.json"));
    }

    // ── Session save/load roundtrip ──────────────────────────────────────────

    #[test]
    fn test_session_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let session = SessionFile {
            version: 1,
            bank_id: "12030000".to_string(),
            bank_url: "https://fints.dkb.de/fints".to_string(),
            blz: "12030000".to_string(),
            user_id: "myuser".to_string(),
            system_id: "sys123".to_string(),
            bpd_version: 5,
            upd_version: 2,
            tan_methods: Vec::new(),
            selected_security_function: "999".to_string(),
            accounts: Vec::new(),
            operation_tan_required: HashMap::new(),
            saved_at: "2024-01-01T00:00:00Z".to_string(),
        };

        save_session(dir.path(), "test", &session).unwrap();
        let loaded = load_session(dir.path(), "test").unwrap();
        assert_eq!(loaded.bank_id, "12030000");
        assert_eq!(loaded.user_id, "myuser");
    }

    #[test]
    fn test_load_session_missing() {
        let dir = tempfile::tempdir().unwrap();
        let result = load_session(dir.path(), "nonexistent");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("No session found") || msg.contains("setup"));
    }
}
