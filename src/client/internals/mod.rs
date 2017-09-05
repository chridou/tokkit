use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use std::time::{Duration, UNIX_EPOCH};

mod request_scheduler;
mod token_updater;

use client::tokenservice::TokenService;
use super::*;

pub type EpochMillis = u64;


pub fn initialize<
    T: Eq + Ord + Send + Sync + Clone + Display + 'static,
    C: Clock + Clone + Send + 'static,
>(
    groups: Vec<ManagedTokenGroup<T>>,
    clock: C,
) -> (Arc<Inner<T>>, mpsc::Sender<ManagerCommand<T>>) {
    let tokens = create_tokens(&groups);
    let states = create_states(groups, clock.now());

    let (tx, rx) = mpsc::channel::<ManagerCommand<T>>();

    let is_running = AtomicBool::new(true);

    let inner = Arc::new(Inner { tokens, is_running });

    start(states, inner.clone(), tx.clone(), rx, clock);

    (inner.clone(), tx)
}

fn create_states<T: Clone>(
    groups: Vec<ManagedTokenGroup<T>>,
    now: EpochMillis,
) -> Vec<Mutex<TokenState<T>>> {
    let mut states = Vec::new();
    let mut idx = 0;
    for group in groups {
        for managed_token in group.managed_tokens {
            states.push(Mutex::new(TokenState {
                token_id: managed_token.token_id.clone(),
                scopes: managed_token.scopes,
                refresh_threshold: group.refresh_threshold,
                warning_threshold: group.warning_threshold,
                last_touched: now,
                refresh_at: now,
                warn_at: now,
                expires_at: now,
                last_notification_at: None,
                token_service: group.token_service.clone(),
                is_initialized: false,
                index: idx,
                is_error: true, // unitialized is also an error.
            }));
            idx += 1;
        }
    }
    states
}

fn create_tokens<T: Eq + Ord + Clone + Display>(
    groups: &[ManagedTokenGroup<T>],
) -> BTreeMap<T, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)> {
    let mut tokens: BTreeMap<T, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)> =
        Default::default();
    let mut idx = 0;
    for group in groups {
        for managed_token in &group.managed_tokens {
            tokens.insert(
                managed_token.token_id.clone(),
                (
                    idx,
                    Mutex::new(Err(ErrorKind::NotInitialized(
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
    states: Vec<Mutex<TokenState<T>>>,
    inner: Arc<Inner<T>>,
    sender: mpsc::Sender<ManagerCommand<T>>,
    receiver: mpsc::Receiver<ManagerCommand<T>>,
    clock: C,
) {
    let states1 = Arc::new(states);
    let states2 = states1.clone();
    let inner1 = inner.clone();
    let sender1 = sender.clone();
    let clock1 = clock.clone();
    thread::spawn(move || {
        let scheduler = request_scheduler::RefreshScheduler::new(
            &*states1,
            &sender1,
            30_000,
            60_000,
            &inner1.is_running,
            &clock1,
        );
        scheduler.start();
    });
    thread::spawn(move || {
        let token_updater = token_updater::TokenUpdater::new(
            &*states2,
            &inner.tokens,
            receiver,
            sender,
            &inner.is_running,
            &clock,
        );
        token_updater.start();
    });
}

pub struct Inner<T> {
    pub tokens: BTreeMap<T, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)>,
    pub is_running: AtomicBool,
}

pub struct TokenState<T> {
    token_id: T,
    scopes: Vec<Scope>,
    refresh_threshold: f32,
    warning_threshold: f32,
    last_touched: EpochMillis,
    refresh_at: EpochMillis,
    warn_at: EpochMillis,
    expires_at: EpochMillis,
    last_notification_at: Option<EpochMillis>,
    token_service: Arc<TokenService + Send + Sync + 'static>,
    is_initialized: bool,
    is_error: bool,
    index: usize,
}

impl<T> Drop for Inner<T> {
    fn drop(&mut self) {
        self.is_running.store(false, Ordering::Relaxed);
    }
}

#[derive(Debug, PartialEq)]
pub enum ManagerCommand<T> {
    ScheduledRefresh(usize, u64),
    ForceRefresh(T, u64),
    RefreshOnError(usize, u64),
    Stop,
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

fn elapsed_millis_from(start_millis: u64, clock: &Clock) -> u64 {
    diff_millis(start_millis, clock.now())
}

fn millis_from_duration(d: Duration) -> u64 {
    (d.as_secs() * 1000) + (d.subsec_nanos() / 1_000_000) as u64
}
