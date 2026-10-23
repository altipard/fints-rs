//! High-level Flow API for the GraphQL layer.
//!
//! Orchestrates the two-step interactive TAN flow:
//! 1. `Flow::initiate()` → challenge info, holds dialog in TanPending/Open
//! 2. `Flow::confirm_and_fetch()` → polls TAN, fetches data

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::{FinTSError, Result};
use crate::protocol::*;
use crate::types::*;
use crate::workflow::*;

// ═══════════════════════════════════════════════════════════════════════════════
// Public result types
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeInfo {
    pub challenge: ChallengeText,
    pub challenge_hhduc: Option<HhdUcData>,
    pub decoupled: bool,
    pub tan_methods: Vec<TanMethod>,
    pub allowed_security_functions: Vec<SecurityFunction>,
    /// If true, skip TAN step — SCA exemption.
    pub no_tan_required: bool,
}

/// Type alias for `FetchOpts` — preferred name in the flow/public API.
/// Both names refer to the same type from the workflow module.
pub use crate::workflow::FetchOpts as FetchOptions;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    pub iban: Iban,
    pub bic: Bic,
    pub balance: Option<AccountBalance>,
    pub transactions: Vec<Transaction>,
    pub holdings: Vec<SecurityHolding>,
    pub system_id: Option<SystemId>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Flow
// ═══════════════════════════════════════════════════════════════════════════════

enum FlowState {
    WaitingForTan {
        dialog: Dialog<TanPending>,
        challenge: TanChallenge,
    },
    Authenticated {
        dialog: Dialog<Open>,
    },
    Done,
}

pub struct Flow {
    bank: AnyBank,
    state: FlowState,
    system_id: SystemId,
}

impl Flow {
    /// Step 1: initiate connection using an already-resolved AnyBank.
    /// Use this when you have a custom BankConfig (e.g. non-registry banks).
    pub async fn initiate_with_bank(
        bank: AnyBank,
        username: &UserId,
        pin: &Pin,
        product_id: &ProductId,
        system_id: Option<&SystemId>,
        target_iban: Option<&Iban>,
        target_bic: Option<&Bic>,
    ) -> Result<(Self, ChallengeInfo)> {
        Self::initiate_inner(bank, username, pin, product_id, system_id, target_iban, target_bic).await
    }

    /// Step 1: initiate connection, get TAN challenge.
    pub async fn initiate(
        bank_id: &str,
        username: &UserId,
        pin: &Pin,
        product_id: &ProductId,
        system_id: Option<&SystemId>,
        target_iban: Option<&Iban>,
        target_bic: Option<&Bic>,
    ) -> Result<(Self, ChallengeInfo)> {
        let bank = bank_ops(bank_id)?;
        Self::initiate_inner(bank, username, pin, product_id, system_id, target_iban, target_bic).await
    }

    async fn initiate_inner(
        bank: AnyBank,
        username: &UserId,
        pin: &Pin,
        product_id: &ProductId,
        system_id: Option<&SystemId>,
        target_iban: Option<&Iban>,
        target_bic: Option<&Bic>,
    ) -> Result<(Self, ChallengeInfo)> {
        let outcome = bank.initiate(
            username, pin, product_id, system_id, target_iban, target_bic,
        ).await?;

        match outcome {
            InitiateOutcome::NeedTan(result) => {
                let info = ChallengeInfo {
                    challenge: result.challenge.challenge.clone(),
                    challenge_hhduc: result.challenge.challenge_hhduc.clone(),      
                    decoupled: result.challenge.decoupled,
                    tan_methods: result.tan_methods,
                    allowed_security_functions: result.allowed_security_functions,
                    no_tan_required: false,
                };
                let flow = Flow {
                    bank,
                    state: FlowState::WaitingForTan {
                        dialog: result.dialog,
                        challenge: result.challenge,
                    },
                    system_id: result.system_id,
                };
                Ok((flow, info))
            }
            InitiateOutcome::Authenticated(result) => {
                let info = ChallengeInfo {
                    challenge: ChallengeText::new(""),
                    challenge_hhduc: None,      
                    decoupled: false,
                    tan_methods: result.tan_methods,
                    allowed_security_functions: result.allowed_security_functions,
                    no_tan_required: true,
                };
                let flow = Flow {
                    bank,
                    state: FlowState::Authenticated { dialog: result.dialog },
                    system_id: result.system_id,
                };
                Ok((flow, info))
            }
        }
    }

    /// Step 2: confirm TAN and fetch everything (balance + transactions + holdings).
    /// Equivalent to `confirm_and_fetch_opts(iban, bic, FetchOpts::all(days))`.
    pub async fn confirm_and_fetch(
        &mut self,
        iban: &str,
        bic: &str,
        days: u32,
    ) -> Result<SyncResult> {
        self.confirm_and_fetch_opts(iban, bic, &FetchOpts::all(days)).await
    }

    /// Step 2 with fine-grained fetch control.
    /// Use `FetchOpts` to choose which data to retrieve in a single dialog.
    /// Fails for non-decoupled TANs, use `confirm_and_fetch_opts_with_tan` for those.
    pub async fn confirm_and_fetch_opts(
        &mut self,
        iban: &str,
        bic: &str,
        opts: &FetchOpts,
    ) -> Result<SyncResult> {
        let mut no_provider = |_: &TanChallenge| -> Result<String> {
            Err(FinTSError::Dialog("a TAN is required but no TAN provider was given".into()))
        };
        self.confirm_and_fetch_opts_with_tan(iban, bic, opts, &mut no_provider).await
    }

    /// Like `confirm_and_fetch_opts`; TANs (init and per order) of non-decoupled
    /// methods are requested from `provider` and submitted with HKTAN process 2.
    pub async fn confirm_and_fetch_opts_with_tan(
        &mut self,
        iban: &str,
        bic: &str,
        opts: &FetchOpts,
        provider: &mut TanProvider,
    ) -> Result<SyncResult> {
        let mut open = self.authenticate(provider).await?;
        let account = self.resolve_account(iban, bic)?;
        let fetch = self.bank.fetch_with_opts_tan(&mut open, &account, opts, provider).await?;
        let sys_id = open.system_id().clone();
        open.end().await.ok();
        Ok(SyncResult {
            iban: Iban::new(iban), bic: Bic::new(bic),
            balance: fetch.balance, transactions: fetch.transactions,
            holdings: fetch.holdings,
            system_id: Some(sys_id),
        })
    }

    /// Complete the init TAN (if any) and keep the dialog open for later use.
    pub async fn confirm_tan_with(&mut self, provider: &mut TanProvider) -> Result<()> {
        let open = self.authenticate(provider).await?;
        self.state = FlowState::Authenticated { dialog: open };
        Ok(())
    }

    /// End the dialog of an authenticated flow.
    pub async fn end(&mut self) -> Result<()> {
        match std::mem::replace(&mut self.state, FlowState::Done) {
            FlowState::Authenticated { dialog } => dialog.end().await,
            other => { self.state = other; Ok(()) }
        }
    }

    /// Turn the current state into an open dialog: poll decoupled TANs,
    /// submit others via `provider` (HKTAN process 2).
    async fn authenticate(&mut self, provider: &mut TanProvider) -> Result<Dialog<Open>> {
        match std::mem::replace(&mut self.state, FlowState::Done) {
            FlowState::WaitingForTan { dialog, challenge } if challenge.decoupled => {
                match dialog.poll(&challenge.task_reference).await? {
                    PollResult::Confirmed(open, _response) => {
                        info!("[Flow] TAN confirmed");
                        Ok(open)
                    }
                    PollResult::Pending(dialog) => {
                        self.state = FlowState::WaitingForTan { dialog, challenge };
                        Err(FinTSError::Dialog(
                            "TAN still pending: user has not yet confirmed in banking app".into()
                        ))
                    }
                }
            }
            FlowState::WaitingForTan { dialog, challenge } => {
                let tan = provider(&challenge)?;
                let (open, _response) = dialog.submit_tan(&challenge.task_reference, &tan).await?;
                info!("[Flow] TAN submitted");
                Ok(open)
            }
            FlowState::Authenticated { dialog } => {
                info!("[Flow] Already authenticated");
                Ok(dialog)
            }
            FlowState::Done => Err(FinTSError::Dialog("Flow already completed".into())),
        }
    }

    /// Step 2 (alternative): confirm TAN and fetch only securities holdings.
    pub async fn confirm_and_fetch_holdings(
        &mut self,
        iban: &str,
        bic: &str,
    ) -> Result<Vec<SecurityHolding>> {
        let state = std::mem::replace(&mut self.state, FlowState::Done);

        match state {
            FlowState::WaitingForTan { dialog, challenge } => {
                let task_reference = challenge.task_reference.clone();
                let poll_result = dialog.poll(&task_reference).await?;

                match poll_result {
                    PollResult::Confirmed(mut open, _response) => {
                        info!("[Flow] TAN confirmed — fetching holdings");
                        let account = self.resolve_account(iban, bic)?;
                        let holdings = self.bank.fetch_holdings(&mut open, &account).await?;
                        open.end().await.ok();
                        Ok(holdings)
                    }
                    PollResult::Pending(dialog) => {
                        self.state = FlowState::WaitingForTan { dialog, challenge };
                        Err(FinTSError::Dialog(
                            "TAN still pending: user has not yet confirmed in banking app".into()
                        ))
                    }
                }
            }
            FlowState::Authenticated { mut dialog } => {
                info!("[Flow] Already authenticated — fetching holdings directly");
                let account = self.resolve_account(iban, bic)?;
                let holdings = self.bank.fetch_holdings(&mut dialog, &account).await?;
                dialog.end().await.ok();
                Ok(holdings)
            }
            FlowState::Done => {
                Err(FinTSError::Dialog("Flow already completed".into()))
            }
        }
    }

    pub fn system_id(&self) -> &SystemId { &self.system_id }

    /// Resolve account with bank's BIC as fallback.
    fn resolve_account(&self, iban: &str, bic: &str) -> Result<Account> {
        let bic = if bic.is_empty() { self.bank.config().bic.as_str() } else { bic };
        Account::new(iban, bic)
    }
}
