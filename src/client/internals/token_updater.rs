use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::{Instant, Duration};

use super::*;

pub struct TokenUpdater<'a> {
    states: &'a [Mutex<TokenState>],
    tokens: &'a BTreeMap<TokenName, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)>,
    receiver: mpsc::Receiver<ManagerCommand>,
    sender: mpsc::Sender<ManagerCommand>,
    is_running: &'a AtomicBool,
}

impl<'a> TokenUpdater<'a> {
    pub fn start(
        states: &'a [Mutex<TokenState>],
        tokens: &'a BTreeMap<TokenName, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)>,
        receiver: mpsc::Receiver<ManagerCommand>,
        sender: mpsc::Sender<ManagerCommand>,
        is_running: &'a AtomicBool,
    ) {
        TokenUpdater {
            states,
            tokens,
            receiver,
            sender,
            is_running,
        }.run_updater_loop();
    }

    fn run_updater_loop(&self) {
        debug!("Starting updater loop");
        while self.is_running.load(Ordering::Relaxed) {
            match self.receiver.recv() {
                Ok(ManagerCommand::ScheduledRefresh(idx, timestamp)) => {
                    let state = &self.states[idx];
                    let token_name = &state.lock().unwrap().name;
                    debug!("Scheduled refresh for token '{}'", token_name);
                    let &(_, ref token) = self.tokens.get(token_name).unwrap();
                    self.refresh_token(state, token, timestamp);
                }
                Ok(ManagerCommand::ForceRefresh(token_name, timestamp)) => {
                    info!("Forced refresh for token '{}'", token_name);
                    let &(idx, ref token) = self.tokens.get(&token_name).unwrap();
                    let state = &self.states[idx];
                    self.refresh_token(state, token, timestamp);
                }
                Ok(ManagerCommand::RefreshOnError(idx, timestamp)) => {
                    let state = &self.states[idx];
                    let token_name = &state.lock().unwrap().name;
                    info!("Refresh on error for token '{}'", token_name);
                    let &(_, ref token) = self.tokens.get(token_name).unwrap();
                    self.refresh_token(state, token, timestamp);
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
        &self,
        state: &Mutex<TokenState>,
        token: &Mutex<StdResult<AccessToken, ErrorKind>>,
        command_timestamp: Instant,
    ) {
        let state: &mut TokenState = &mut *state.lock().unwrap();
        if state.last_touched < command_timestamp {
            let result = state.token_service.get_token(&state.scopes);
            let do_update = if let Err(ref err) = result {
                info!(
                    "Scheduling refresh on error for token {}: {}",
                    state.name,
                    err
                );
                self.sender
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
}

fn update_token(
    rsp: TokenServiceResult,
    state: &mut TokenState,
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
