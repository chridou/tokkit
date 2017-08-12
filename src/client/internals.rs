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
    is_initialized: bool,
    is_error: bool,
    index: usize,
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
    let min_scheduler_cycle_dur = Duration::from_secs(10);

    let states1 = Arc::new(states);
    let states2 = states1.clone();
    let inner1 = inner.clone();
    let sender1 = sender.clone();
    thread::spawn(move || {
        run_scheduler_loop(
            &*states1,
            &inner1.is_running,
            sender1,
            min_scheduler_cycle_dur,
        )
    });
    thread::spawn(move || {
        run_updater_loop(
            &*states2,
            &inner.tokens,
            receiver,
            sender,
            &inner.is_running,
        )
    });
}

pub enum ManagerCommand {
    ScheduledRefresh(usize, Instant),
    ForceRefresh(TokenName, Instant),
    RefreshOnError(usize, Instant),
    Stop,
}

fn run_scheduler_loop(
    states: &[Mutex<ManagedTokenState>],
    is_running: &AtomicBool,
    sender: mpsc::Sender<ManagerCommand>,
    min_cycle_dur: Duration,
) {
    debug!("Starting scheduler loop");
    while is_running.load(Ordering::Relaxed) {
        let start = Instant::now();

        do_a_scheduling_round(states, &sender);

        let elapsed = Instant::now() - start;
        let sleep_dur = min_cycle_dur.checked_sub(elapsed).unwrap_or(
            Duration::from_secs(0),
        );
        thread::sleep(sleep_dur);
    }
    info!("Scheduler loop exited.")
}

fn do_a_scheduling_round(
    states: &[Mutex<ManagedTokenState>],
    sender: &mpsc::Sender<ManagerCommand>,
) {
    for (idx, state) in states.iter().enumerate() {
        let state = &mut *state.lock().unwrap();
        if state.refresh_at <= Instant::now() {

            if let Err(err) = sender.send(ManagerCommand::ScheduledRefresh(idx, Instant::now())) {
                error!("Could not send refresh command: {}", err);
                break;
            };

            if state.is_initialized {
                check_log_warnings(state);
            }
        }
    }
}

fn check_log_warnings(state: &ManagedTokenState) {
    let now = Instant::now();
    if state.expires_at < now {
        warn!(
            "Token {} expired {:.2} minutes ago.",
            state.name,
            (now - state.expires_at).as_secs() as f64 / 60.0
        );
    } else if state.warn_at < now {
        warn!(
            "Token {} expires in {:.2} minutes.",
            state.name,
            (state.expires_at - now).as_secs() as f64 / 60.0
        );
    }
}

fn run_updater_loop(
    states: &[Mutex<ManagedTokenState>],
    tokens: &BTreeMap<TokenName, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)>,
    receiver: mpsc::Receiver<ManagerCommand>,
    sender: mpsc::Sender<ManagerCommand>,
    is_running: &AtomicBool,
) {
    debug!("Starting updater loop");
    while is_running.load(Ordering::Relaxed) {
        match receiver.recv() {
            Ok(ManagerCommand::ScheduledRefresh(idx, timestamp)) => {
                let state = &states[idx];
                let token_name = &state.lock().unwrap().name;
                debug!("Scheduled refresh for token '{}'", token_name);
                let &(_, ref token) = tokens.get(token_name).unwrap();
                refresh_token(state, token, timestamp, &sender);
            }
            Ok(ManagerCommand::ForceRefresh(token_name, timestamp)) => {
                info!("Forced refresh for token '{}'", token_name);
                let &(idx, ref token) = tokens.get(&token_name).unwrap();
                let state = &states[idx];
                refresh_token(state, token, timestamp, &sender);
            }
            Ok(ManagerCommand::RefreshOnError(idx, timestamp)) => {
                let state = &states[idx];
                let token_name = &state.lock().unwrap().name;
                info!("Refresh on error for token '{}'", token_name);
                let &(_, ref token) = tokens.get(token_name).unwrap();
                refresh_token(state, token, timestamp, &sender);
            }
            Ok(ManagerCommand::Stop) => {
                warn!("Received stop command.");
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
    command_timestamp: Instant,
    sender: &mpsc::Sender<ManagerCommand>,
) {
    let state: &mut ManagedTokenState = &mut *state.lock().unwrap();
    if state.last_touched < command_timestamp {
        let result = state.token_service.get_token(&state.scopes);
        let do_update = if let Err(ref err) = result {
            info!(
                "Scheduling refresh on error for token {}: {}",
                state.name,
                err
            );
            sender
                .send(ManagerCommand::RefreshOnError(state.index, Instant::now()))
                .unwrap();

            if state.is_error {
                error!(
                    "Received an error for token '{}' and the token is already in error state! \
                    Error: {}",
                    state.name,
                    err
                );
                true
            } else if state.expires_at < Instant::now() {
                error!(
                    "Received an error for token '{}' and the token has already expired! \
                    Error: {}",
                    state.name,
                    err
                );
                true
            } else {
                error!(
                    "Received an error for token '{}'. Will not update the \
                    token because it is still valid. \
                    Error: {}",
                    state.name,
                    err
                );
                false
            }
        } else {
            debug!("Update received token data");
            true
        };
        if do_update {
            update_token(result, state, token);
        }
    }
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
            state.is_initialized = true;
            state.is_error = false;
            info!(
                "Refreshed token '{}' after {:.2} minutes. New token will expire in {:.2} minutes. \
                Refresh in {:.2} minutes.",
                state.name,
                ((state.expires_at - now).as_secs() as f64 / 60.0),
                token_response.expires_in.as_secs() as f64 / 60.0,
                ((state.refresh_at - now).as_secs() as f64 / 60.0),
            );
        }
        Err(err) => {
            {
                *token.lock().unwrap() = Err(err.into())
            };
            let now = Instant::now();
            state.last_touched = now;
            state.expires_at = now;
            state.refresh_at = now;
            state.warn_at = now;
            state.is_initialized = true;
            state.is_error = true;
        }
    }
}
