use std::collections::BTreeMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

mod request_scheduler;
mod token_updater;

use super::*;
use crate::token_manager::token_provider::AccessTokenProvider;

pub type EpochMillis = u64;

pub fn initialize<
    T: Eq + Ord + Send + Sync + Clone + Display + 'static,
    C: Clock + Clone + Send + 'static,
>(
    groups: Vec<ManagedTokenGroup<T>>,
    clock: C,
) -> (Inner<T>, mpsc::Sender<ManagerCommand<T>>) {
    let tokens = Arc::new(create_tokens(&groups));
    let rows = create_rows(groups, clock.now());

    let (tx, rx) = mpsc::channel::<ManagerCommand<T>>();

    let is_running = Arc::new(AtomicBool::new(true));

    let inner = Inner { tokens, is_running };

    start(rows, inner.clone(), tx.clone(), rx, clock);

    (inner, tx)
}

fn create_rows<T: Clone>(
    groups: Vec<ManagedTokenGroup<T>>,
    now: EpochMillis,
) -> Vec<Mutex<TokenRow<T>>> {
    let mut states = Vec::new();
    for group in groups {
        for managed_token in group.managed_tokens {
            states.push(Mutex::new(TokenRow {
                token_id: managed_token.token_id.clone(),
                scopes: managed_token.scopes,
                refresh_threshold: group.refresh_threshold,
                warning_threshold: group.warning_threshold,
                last_touched: now,
                refresh_at: now,
                warn_at: now,
                expires_at: now,
                scheduled_for: now,
                token_state: TokenState::Uninitialized,
                last_notification_at: None,
                token_provider: group.token_provider.clone(),
            }));
        }
    }
    states
}

fn create_tokens<T: Eq + Ord + Clone + Display>(
    groups: &[ManagedTokenGroup<T>],
) -> BTreeMap<T, (usize, Mutex<StdResult<AccessToken, TokenErrorKind>>)> {
    let mut tokens: BTreeMap<T, (usize, Mutex<StdResult<AccessToken, TokenErrorKind>>)> =
        Default::default();
    let mut idx = 0;
    for group in groups {
        for managed_token in &group.managed_tokens {
            tokens.insert(
                managed_token.token_id.clone(),
                (
                    idx,
                    Mutex::new(Err(TokenErrorKind::NotInitialized(
                        managed_token.token_id.to_string(),
                    ))),
                ),
            );
            idx += 1;
        }
    }
    tokens
}

fn start<
    T: Eq + Ord + Send + Sync + Clone + Display + 'static,
    C: Clock + Clone + Send + 'static,
>(
    rows: Vec<Mutex<TokenRow<T>>>,
    inner: Inner<T>,
    sender: mpsc::Sender<ManagerCommand<T>>,
    receiver: mpsc::Receiver<ManagerCommand<T>>,
    clock: C,
) {
    let rows1 = Arc::new(rows);
    let rows2 = rows1.clone();
    let inner1 = inner.clone();
    let clock1 = clock.clone();
    thread::spawn(move || {
        let scheduler = request_scheduler::RefreshScheduler::new(
            &*rows1,
            &sender,
            500,
            10_000,
            &inner1.is_running,
            &clock1,
        );
        scheduler.start();
    });
    thread::spawn(move || {
        let token_updater = token_updater::TokenUpdater::new(
            &*rows2,
            &inner.tokens,
            receiver,
            &inner.is_running,
            &clock,
        );
        token_updater.start();
    });
}

#[derive(Clone)]
pub struct Inner<T> {
    pub tokens: Arc<BTreeMap<T, (usize, Mutex<StdResult<AccessToken, TokenErrorKind>>)>>,
    pub is_running: Arc<AtomicBool>,
}

impl<T: Eq + Ord + Clone + Display> Inner<T> {
    pub fn get_access_token(&self, token_id: &T) -> TokenResult<AccessToken> {
        match self.tokens.get(&token_id) {
            Some((_, guard)) => match &*guard.lock().unwrap() {
                Ok(token) => Ok(token.clone()),
                Err(err) => Err(err.clone().into()),
            },
            None => Err(TokenErrorKind::NoToken(token_id.to_string()).into()),
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum TokenState {
    Uninitialized,
    Initializing,
    Ok,
    OkPending,
    Error,
    ErrorPending,
}

impl TokenState {
    pub fn is_refresh_pending(&self) -> bool {
        match *self {
            TokenState::Initializing | TokenState::OkPending | TokenState::ErrorPending => true,
            _ => false,
        }
    }

    pub fn is_uninitialized(&self) -> bool {
        match *self {
            TokenState::Uninitialized | TokenState::Initializing => true,
            _ => false,
        }
    }
}

pub struct TokenRow<T> {
    token_id: T,
    scopes: Vec<Scope>,
    refresh_threshold: f32,
    warning_threshold: f32,
    last_touched: EpochMillis,
    refresh_at: EpochMillis,
    warn_at: EpochMillis,
    expires_at: EpochMillis,
    scheduled_for: EpochMillis,
    token_state: TokenState,
    last_notification_at: Option<EpochMillis>,
    token_provider: Arc<dyn AccessTokenProvider + Send + Sync + 'static>,
}

#[derive(Debug, PartialEq)]
pub enum ManagerCommand<T> {
    ScheduledRefresh(usize, u64),
    ForceRefresh(T, u64),
    RefreshOnError(usize, u64),
}

pub trait Clock {
    fn now(&self) -> EpochMillis;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> EpochMillis {
        millis_from_duration(UNIX_EPOCH.elapsed().unwrap())
    }
}

impl Clone for SystemClock {
    fn clone(&self) -> Self
    where
        Self: Sized,
    {
        SystemClock
    }
}

fn diff_millis(start_millis: u64, end_millis: u64) -> u64 {
    if start_millis > end_millis {
        0
    } else {
        end_millis - start_millis
    }
}

fn minus_millis(from: u64, subtract: u64) -> u64 {
    if subtract > from {
        0
    } else {
        from - subtract
    }
}

fn elapsed_millis_from(start_millis: u64, clock: &dyn Clock) -> u64 {
    diff_millis(start_millis, clock.now())
}

fn millis_from_duration(d: Duration) -> u64 {
    (d.as_secs() * 1000) + d.subsec_millis() as u64
}
