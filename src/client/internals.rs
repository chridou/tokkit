use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use std::time::{Instant, Duration};

use client::tokenservice::{TokenService, TokenServiceResponse};
use super::*;

pub fn initialize(groups: Vec<ManagedTokenGroup>) -> (Arc<Inner>, mpsc::Sender<ManagerCommand>) {
    let mut states = Vec::new();
    let mut tokens: BTreeMap<TokenName, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)> =
        Default::default();
    let mut idx = 0;
    for group in groups {
        for managed_token in group.managed_tokens {
            let now = Instant::now();
            states.push(Mutex::new(ManagedTokenState {
                name: managed_token.name.clone(),
                scopes: managed_token.scopes,
                refresh_threshold: group.refresh_threshold,
                warning_threshold: group.warning_threshold,
                last_touched: now,
                refresh_at: now,
                warn_at: now,
                expires_at: now,
                token_service: group.token_service.clone(),
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

    start_manager_loop(states, inner.clone(), tx.clone(), rx);

    (inner.clone(), tx)
}

pub struct Inner {
    pub tokens: BTreeMap<TokenName, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)>,
    pub is_running: AtomicBool,
}

struct ManagedTokenState {
    name: TokenName,
    scopes: Vec<Scope>,
    refresh_threshold: f32,
    warning_threshold: f32,
    last_touched: Instant,
    refresh_at: Instant,
    warn_at: Instant,
    expires_at: Instant,
    token_service: Arc<TokenService + Send + Sync + 'static>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.is_running.store(false, Ordering::Relaxed);
    }
}

fn start_manager_loop(
    states: Vec<Mutex<ManagedTokenState>>,
    inner: Arc<Inner>,
    sender: mpsc::Sender<ManagerCommand>,
    receiver: mpsc::Receiver<ManagerCommand>,
) {
    let states1 = Arc::new(states);
    let states2 = states1.clone();
    let inner1 = inner.clone();
    thread::spawn(move || {
        run_scheduler_loop(&*states1, &inner1.is_running, sender)
    });
    thread::spawn(move || {
        run_updater_loop(&*states2, &inner.tokens, receiver, &inner.is_running)
    });
}

pub enum ManagerCommand {
    ScheduledRefresh(usize),
    ForceRefresh(TokenName),
    Stop,
}

fn run_scheduler_loop(
    states: &[Mutex<ManagedTokenState>],
    is_running: &AtomicBool,
    sender: mpsc::Sender<ManagerCommand>,
) {
    debug!("Starting scheduler loop");
    while is_running.load(Ordering::Relaxed) {}
    info!("Scheduler loop exited.")
}

fn run_updater_loop(
    states: &[Mutex<ManagedTokenState>],
    tokens: &BTreeMap<TokenName, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)>,
    receiver: mpsc::Receiver<ManagerCommand>,
    is_running: &AtomicBool,
) {
    debug!("Starting updater loop");
    while is_running.load(Ordering::Relaxed) {
        match receiver.recv() {
            Ok(ManagerCommand::ScheduledRefresh(idx)) => {
                let state = &states[idx];
                let token_name = &state.lock().unwrap().name;
                debug!("Scheduled refresh for token '{}'", token_name);
                let &(_, ref token) = tokens.get(token_name).unwrap();
                refresh_token(state, token);
            }
            Ok(ManagerCommand::ForceRefresh(token_name)) => {
                info!("Forced refresh for token '{}'", token_name);
                let &(idx, ref token) = tokens.get(&token_name).unwrap();
                let state = &states[idx];
                refresh_token(state, token);
            }
            Ok(ManagerCommand::Stop) => {
                info!("Received stop command.");
                break;
            }
            Err(err) => {
                error!("Failed to receive command from channel: {}", err);
                break;
            }
        }
    }
    info!("Updater loop exited.")
}

fn refresh_token(
    state: &Mutex<ManagedTokenState>,
    token: &Mutex<StdResult<AccessToken, ErrorKind>>,
) {
    let state: &mut ManagedTokenState = &mut *state.lock().unwrap();
    let result = state.token_service.get_token(&state.scopes);
    update_token(result, state, token);
}

fn update_token(
    rsp: TokenServiceResult,
    state: &mut ManagedTokenState,
    token: &Mutex<StdResult<AccessToken, ErrorKind>>,
) {
    match rsp {
        Ok(token_response) => {
            {
                *token.lock().unwrap() = Ok(token_response.token)
            };
            let now = Instant::now();
            state.last_touched = now;
            state.expires_at = now + token_response.expires_in;
            state.refresh_at = now +
                Duration::from_secs(
                    (token_response.expires_in.as_secs() as f32 * state.refresh_threshold) as u64,
                );
            state.warn_at = now +
                Duration::from_secs(
                    (token_response.expires_in.as_secs() as f32 * state.warning_threshold) as u64,
                );
            info!(
                "Refreshed token '{}' after {} minutes. New token will expire in {} minutes.",
                state.name,
                ((now - state.expires_at).as_secs() as f64 / 60.0),
                token_response.expires_in.as_secs() as f64 / 60.0
            );
        }
        Err(err) => {
            error!("Failed to refresh token '{}': {}", state.name, err);
            {
                *token.lock().unwrap() = Err(err.into())
            };
            let now = Instant::now();
            state.last_touched = now;
            state.expires_at = now;
            state.refresh_at = now;
            state.warn_at = now;
        }
    }
}
