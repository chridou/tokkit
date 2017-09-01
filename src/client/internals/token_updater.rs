use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::{Instant, Duration};
use backoff::{Error as BError, ExponentialBackoff, Operation};

use super::*;

pub struct TokenUpdater<'a, T: 'a> {
    states: &'a [Mutex<TokenState<T>>],
    tokens: &'a BTreeMap<T, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)>,
    receiver: mpsc::Receiver<ManagerCommand<T>>,
    sender: mpsc::Sender<ManagerCommand<T>>,
    is_running: &'a AtomicBool,
    clock: &'a Clock,
}

impl<'a, T: Eq + Ord + Send + Clone + Display> TokenUpdater<'a, T> {
    pub fn start(
        states: &'a [Mutex<TokenState<T>>],
        tokens: &'a BTreeMap<T, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)>,
        receiver: mpsc::Receiver<ManagerCommand<T>>,
        sender: mpsc::Sender<ManagerCommand<T>>,
        is_running: &'a AtomicBool,
        clock: &'a Clock,
    ) {
        TokenUpdater {
            states,
            tokens,
            receiver,
            sender,
            is_running,
            clock,
        }.run_updater_loop();
    }

    fn run_updater_loop(&self) {
        debug!("Starting updater loop");
        while self.is_running.load(Ordering::Relaxed) {
            match self.receiver.recv() {
                Ok(cmd) => {
                    if !self.on_command(cmd) {
                        break;
                    }
                }
                Err(err) => {
                    error!("Failed to receive command from channel: {}", err);
                    break;
                }
            }
        }
        info!("Updater loop exited.")
    }

    fn on_command(&self, cmd: ManagerCommand<T>) -> bool {
        match cmd {
            ManagerCommand::ScheduledRefresh(idx, timestamp) => {
                let state = &self.states[idx];
                let token_id = &state.lock().unwrap().token_id;
                debug!("Scheduled refresh for token '{}'", token_id);
                let &(_, ref token) = self.tokens.get(token_id).unwrap();
                self.refresh_token(state, token, timestamp);
                true
            }
            ManagerCommand::ForceRefresh(token_id, timestamp) => {
                info!("Forced refresh for token '{}'", token_id);
                let &(idx, ref token) = self.tokens.get(&token_id).unwrap();
                let state = &self.states[idx];
                self.refresh_token(state, token, timestamp);
                true
            }
            ManagerCommand::RefreshOnError(idx, timestamp) => {
                let state = &self.states[idx];
                let token_id = &state.lock().unwrap().token_id;
                info!("Refresh on error for token '{}'", token_id);
                let &(_, ref token) = self.tokens.get(token_id).unwrap();
                self.refresh_token(state, token, timestamp);
                true
            }
            ManagerCommand::Stop => {
                warn!("Received stop command.");
                false
            }
        }
    }

    fn refresh_token(
        &self,
        state: &Mutex<TokenState<T>>,
        token: &Mutex<StdResult<AccessToken, ErrorKind>>,
        command_timestamp: u64,
    ) {
        let state: &mut TokenState<T> = &mut *state.lock().unwrap();
        if state.last_touched < command_timestamp {
            let result = call_token_service(&*state.token_service, &state.scopes);
            let do_update = if let Err(ref err) = result {
                info!(
                    "Scheduling refresh on error for token {}: {}",
                    state.token_id,
                    err
                );
                self.sender
                    .send(ManagerCommand::RefreshOnError(state.index, self.clock.now()))
                    .unwrap();

                if state.is_error {
                    error!(
                        "Received an error for token '{}' and the token is already in error state! \
                    Error: {}",
                        state.token_id,
                        err
                    );
                    true
                } else if state.expires_at < self.clock.now() {
                    error!(
                        "Received an error for token '{}' and the token has already expired! \
                    Error: {}",
                        state.token_id,
                        err
                    );
                    true
                } else {
                    error!(
                        "Received an error for token '{}'. Will not update the \
                    token because it is still valid. \
                    Error: {}",
                        state.token_id,
                        err
                    );
                    false
                }
            } else {
                debug!("Update received token data");
                true
            };
            if do_update {
                update_token(result, state, token, self.clock);
            }
        }
    }
}

fn update_token<T: Display>(
    rsp: TokenServiceResult,
    state: &mut TokenState<T>,
    token: &Mutex<StdResult<AccessToken, ErrorKind>>,
    clock: &Clock,
) {
    match rsp {
        Ok(token_response) => {
            {
                *token.lock().unwrap() = Ok(token_response.token)
            };
            let now = clock.now();
            let expires_in_ms = millis_from_duration(token_response.expires_in);
            state.last_touched = now;
            state.expires_at = now + expires_in_ms;
            state.refresh_at = now +
                (expires_in_ms as f32 * state.refresh_threshold) as u64;
            state.warn_at = now +
                (expires_in_ms as f32 * state.warning_threshold) as u64;
            state.is_initialized = true;
            state.is_error = false;
            info!(
                "Refreshed token '{}' after {:.2} minutes. New token will expire in {:.2} minutes. \
                Refresh in {:.2} minutes.",
                state.token_id,
                diff_millis(state.expires_at, now) as f64 / (60.0 * 1000.0),
                token_response.expires_in.as_secs() as f64 / 60.0,
                diff_millis(state.refresh_at, now) as f64 / (60.0 * 1000.0),
            );
        }
        Err(err) => {
            {
                *token.lock().unwrap() = Err(err.into())
            };
            let now = clock.now();
            state.last_touched = now;
            state.expires_at = now;
            state.refresh_at = now;
            state.warn_at = now;
            state.is_initialized = true;
            state.is_error = true;
        }
    }
}

fn call_token_service(service: &TokenService, scopes: &[Scope]) -> TokenServiceResult {
    let mut call = || -> StdResult<TokenServiceResponse, BError<TokenServiceError>> {
        match service.get_token(scopes) {
            Ok(rsp) => Ok(rsp),
            Err(err @ TokenServiceError::Server(_)) => {
                warn!("Call to token service failed: {}", err);
                Err(BError::Transient(err))
            }
            Err(err @ TokenServiceError::Connection(_)) => {
                warn!("Call to token service failed: {}", err);
                Err(BError::Transient(err))
            }
            Err(err @ TokenServiceError::Credentials(_)) => {
                warn!("Call to token service failed: {}", err);
                Err(BError::Transient(err))
            }
            Err(err @ TokenServiceError::Other(_)) => {
                warn!("Call to token service failed: {}", err);
                Err(BError::Transient(err))
            }
            Err(err @ TokenServiceError::Parse(_)) => Err(BError::Permanent(err)),
            Err(err @ TokenServiceError::Client(_)) => Err(BError::Permanent(err)),
        }
    };

    let mut backoff = ExponentialBackoff::default();

    call.retry(&mut backoff).map_err(|err| match err {
        BError::Transient(inner) => inner,
        BError::Permanent(inner) => inner,
    })
}
