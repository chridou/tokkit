use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use std::time::{Instant, Duration};

mod request_scheduler;
mod token_updater;

use client::tokenservice::TokenService;
use super::*;

pub fn initialize(groups: Vec<ManagedTokenGroup>) -> (Arc<Inner>, mpsc::Sender<ManagerCommand>) {
    let mut states = Vec::new();
    let mut tokens: BTreeMap<TokenName, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)> =
        Default::default();
    let mut idx = 0;
    for group in groups {
        for managed_token in group.managed_tokens {
            let now = Instant::now();
            states.push(Mutex::new(TokenState {
                name: managed_token.name.clone(),
                scopes: managed_token.scopes,
                refresh_threshold: group.refresh_threshold,
                warning_threshold: group.warning_threshold,
                last_touched: now,
                refresh_at: now,
                warn_at: now,
                expires_at: now,
                last_notification_at: now - Duration::from_secs(60 * 60 * 24),
                token_service: group.token_service.clone(),
                is_initialized: false,
                index: idx,
                is_error: true, // unitialized is also an error.
            }));
            tokens.insert(managed_token.name.clone(), (
                idx,
                Mutex::new(
                    Err(ErrorKind::NotInitialized(
                        managed_token.name,
                    )),
                ),
            ));
            idx += 1;
        }
    }

    let (tx, rx) = mpsc::channel::<ManagerCommand>();

    let is_running = AtomicBool::new(true);

    let inner = Arc::new(Inner { tokens, is_running });

    start(states, inner.clone(), tx.clone(), rx);

    (inner.clone(), tx)
}

fn start(
    states: Vec<Mutex<TokenState>>,
    inner: Arc<Inner>,
    sender: mpsc::Sender<ManagerCommand>,
    receiver: mpsc::Receiver<ManagerCommand>,
) {
    let states1 = Arc::new(states);
    let states2 = states1.clone();
    let inner1 = inner.clone();
    let sender1 = sender.clone();
    thread::spawn(move || {
        request_scheduler::RefreshScheduler::start(
            &*states1,
            &sender1,
            Duration::from_secs(30),
            Duration::from_secs(60),
            &inner1.is_running,
        )
    });
    thread::spawn(move || {
        token_updater::TokenUpdater::start(
            &*states2,
            &inner.tokens,
            receiver,
            sender,
            &inner.is_running,
        )
    });
}

pub struct Inner {
    pub tokens: BTreeMap<TokenName, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)>,
    pub is_running: AtomicBool,
}

pub struct TokenState {
    name: TokenName,
    scopes: Vec<Scope>,
    refresh_threshold: f32,
    warning_threshold: f32,
    last_touched: Instant,
    refresh_at: Instant,
    warn_at: Instant,
    expires_at: Instant,
    last_notification_at: Instant,
    token_service: Arc<TokenService + Send + Sync + 'static>,
    is_initialized: bool,
    is_error: bool,
    index: usize,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.is_running.store(false, Ordering::Relaxed);
    }
}

pub enum ManagerCommand {
    ScheduledRefresh(usize, Instant),
    ForceRefresh(TokenName, Instant),
    RefreshOnError(usize, Instant),
    Stop,
}
