use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::mpsc;
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
    pub fn new(
        states: &'a [Mutex<TokenState<T>>],
        tokens: &'a BTreeMap<T, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)>,
        receiver: mpsc::Receiver<ManagerCommand<T>>,
        sender: mpsc::Sender<ManagerCommand<T>>,
        is_running: &'a AtomicBool,
        clock: &'a Clock,
    ) -> Self {
        TokenUpdater {
            states,
            tokens,
            receiver,
            sender,
            is_running,
            clock,
        }
    }

    pub fn start(&self) {
        self.run_updater_loop();
    }

    fn run_updater_loop(&self) {
        debug!("Starting updater loop");
        while self.is_running.load(Ordering::Relaxed) {
            match self.next_command() {
                Err(err) => {
                    error!("{}", err);
                    break;
                }
                Ok(true) => {}
                Ok(false) => break,
            }
        }
        info!("Updater loop exited.")
    }

    fn next_command(&self) -> StdResult<bool, String> {
        match self.receiver.recv() {
            Ok(cmd) => Ok(self.on_command(cmd)),
            Err(err) => Err(format!("Failed to receive command from channel: {}", err)),
        }
    }

    fn on_command(&self, cmd: ManagerCommand<T>) -> bool {
        match cmd {
            ManagerCommand::ScheduledRefresh(idx, timestamp) => {
                let state = &self.states[idx];
                let token_id = &state.lock().unwrap().token_id.clone();
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
                let token_id = &state.lock().unwrap().token_id.clone();
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
        if state.last_touched < command_timestamp || !state.is_initialized {
            let result = call_token_service(&*state.token_provider, &state.scopes);
            let do_update = if let Err(ref err) = result {
                info!(
                    "Scheduling refresh on error for token {}: {}",
                    state.token_id,
                    err
                );
                self.sender
                    .send(ManagerCommand::RefreshOnError(
                        state.index,
                        self.clock.now(),
                    ))
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
    rsp: AccessTokenProviderResult,
    state: &mut TokenState<T>,
    token: &Mutex<StdResult<AccessToken, ErrorKind>>,
    clock: &Clock,
) {
    match rsp {
        Ok(token_response) => {
            {
                *token.lock().unwrap() = Ok(token_response.access_token)
            };
            let now = clock.now();
            let expires_in_ms = millis_from_duration(token_response.expires_in);
            state.last_touched = now;
            state.expires_at = now + expires_in_ms;
            state.refresh_at = now + (expires_in_ms as f32 * state.refresh_threshold) as u64;
            state.warn_at = now + (expires_in_ms as f32 * state.warning_threshold) as u64;
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

fn call_token_service(
    provider: &AccessTokenProvider,
    scopes: &[Scope],
) -> AccessTokenProviderResult {
    let mut call =
        || -> StdResult<AuthorizationServerResponse, BError<AccessTokenProviderError>> {
            match provider.request_access_token(scopes) {
                Ok(rsp) => Ok(rsp),
                Err(err @ AccessTokenProviderError::Server(_)) => {
                    warn!("Call to token service failed: {}", err);
                    Err(BError::Transient(err))
                }
                Err(err @ AccessTokenProviderError::Connection(_)) => {
                    warn!("Call to token service failed: {}", err);
                    Err(BError::Transient(err))
                }
                Err(err @ AccessTokenProviderError::Credentials(_)) => {
                    warn!("Call to token service failed: {}", err);
                    Err(BError::Transient(err))
                }
                Err(err @ AccessTokenProviderError::Other(_)) => {
                    warn!("Call to token service failed: {}", err);
                    Err(BError::Transient(err))
                }
                Err(err @ AccessTokenProviderError::Parse(_)) => Err(BError::Permanent(err)),
                Err(err @ AccessTokenProviderError::Client(_)) => Err(BError::Permanent(err)),
            }
        };

    let mut backoff = ExponentialBackoff::default();

    call.retry(&mut backoff).map_err(|err| match err {
        BError::Transient(inner) => inner,
        BError::Permanent(inner) => inner,
    })
}

#[cfg(test)]
mod test {
    use std::sync::{Arc, Mutex};
    use std::cell::Cell;
    use std::rc::Rc;
    use std::sync::mpsc;
    use std::sync::atomic::AtomicBool;
    use client::*;
    use super::*;

    #[derive(Clone)]
    struct TestClock {
        time: Rc<Cell<u64>>,
    }

    impl TestClock {
        pub fn new() -> Self {
            TestClock {
                time: Rc::new(Cell::new(0)),
            }
        }

        pub fn inc(&self, by_ms: u64) {
            let past = self.time.get();
            self.time.set(past + by_ms);
        }

        pub fn set(&self, ms: u64) {
            self.time.set(ms);
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> u64 {
            self.time.get()
        }
    }

    struct DummyAccessTokenProvider {
        counter: Arc<Mutex<u32>>,
    }

    impl DummyAccessTokenProvider {
        pub fn new() -> Self {
            DummyAccessTokenProvider {
                counter: Arc::new(Mutex::new(0)),
            }
        }
    }

    impl AccessTokenProvider for DummyAccessTokenProvider {
        fn request_access_token(&self, scopes: &[Scope]) -> AccessTokenProviderResult {
            let c: &mut u32 = &mut *self.counter.lock().unwrap();
            let res = Ok(AuthorizationServerResponse {
                access_token: AccessToken::new(c.to_string()),
                expires_in: Duration::from_secs(1),
            });
            *c += 1;
            res
        }
    }

    fn create_data() -> (
        Vec<Mutex<TokenState<&'static str>>>,
        BTreeMap<&'static str, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)>,
    ) {
        let mut groups = Vec::default();
        groups.push(
            ManagedTokenGroupBuilder::single_token(
                "token",
                vec![Scope::new("scope")],
                DummyAccessTokenProvider::new(),
            ).build()
                .unwrap(),
        );
        let tokens = create_tokens(&groups);
        let states = create_states(groups, 0);
        (states, tokens)
    }

    #[test]
    fn clock_test() {
        let clock1 = TestClock::new();
        let clock2 = clock1.clone();
        clock1.inc(100);
        assert_eq!(100, clock2.now());
    }

    #[test]
    fn initial_state_is_correct() {
        let (states, _) = create_data();
        let state = states[0].lock().unwrap();
        assert_eq!("token", state.token_id);
        assert_eq!(vec![Scope::new("scope")], state.scopes);
        assert_eq!(0.75, state.refresh_threshold);
        assert_eq!(0.85, state.warning_threshold);
        assert_eq!(0, state.refresh_at);
        assert_eq!(0, state.warn_at);
        assert_eq!(0, state.expires_at);
        assert_eq!(None, state.last_notification_at);
        assert_eq!(false, state.is_initialized);
        assert_eq!(true, state.is_error);
        assert_eq!(0, state.index);
    }

    #[test]
    fn initializes_token_when_time_did_not_increase() {
        let (tx, rx) = mpsc::channel();
        let is_running = AtomicBool::new(true);
        let clock = TestClock::new();
        let (states, tokens) = create_data();

        let updater = TokenUpdater::new(&states, &tokens, rx, tx.clone(), &is_running, &clock);

        clock.set(0);
        updater.on_command(ManagerCommand::ScheduledRefresh(0, clock.now()));
        {
            let state = states[0].lock().unwrap();
            assert_eq!("token", state.token_id);
            assert_eq!(vec![Scope::new("scope")], state.scopes);
            assert_eq!(0, state.last_touched);
            assert_eq!(750, state.refresh_at);
            assert_eq!(850, state.warn_at);
            assert_eq!(1000, state.expires_at);
            assert_eq!(None, state.last_notification_at);
            assert_eq!(true, state.is_initialized);
            assert_eq!(false, state.is_error);
            assert_eq!(0, state.index);
        }
        assert_eq!(
            "0",
            &tokens
                .get("token")
                .unwrap()
                .1
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .0
        );
    }

    #[test]
    fn does_not_initialize_token_twice_when_time_did_not_increase() {
        let (tx, rx) = mpsc::channel();
        let is_running = AtomicBool::new(true);
        let clock = TestClock::new();
        let (states, tokens) = create_data();

        let updater = TokenUpdater::new(&states, &tokens, rx, tx.clone(), &is_running, &clock);

        clock.set(0);
        updater.on_command(ManagerCommand::ScheduledRefresh(0, clock.now()));
        {
            let state = states[0].lock().unwrap();
            assert_eq!("token", state.token_id);
            assert_eq!(vec![Scope::new("scope")], state.scopes);
            assert_eq!(0, state.last_touched);
            assert_eq!(750, state.refresh_at);
            assert_eq!(850, state.warn_at);
            assert_eq!(1000, state.expires_at);
            assert_eq!(None, state.last_notification_at);
            assert_eq!(true, state.is_initialized);
            assert_eq!(false, state.is_error);
            assert_eq!(0, state.index);
        }
        assert_eq!(
            "0",
            &tokens
                .get("token")
                .unwrap()
                .1
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .0
        );

        updater.on_command(ManagerCommand::ScheduledRefresh(0, clock.now()));
        {
            let state = states[0].lock().unwrap();
            assert_eq!(0, state.last_touched);
            assert_eq!(750, state.refresh_at);
            assert_eq!(850, state.warn_at);
            assert_eq!(1000, state.expires_at);
            assert_eq!(None, state.last_notification_at);
        }
        assert_eq!(
            "0",
            &tokens
                .get("token")
                .unwrap()
                .1
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .0
        );
    }

    #[test]
    fn initializes_token_when_time_increased() {
        let (tx, rx) = mpsc::channel();
        let is_running = AtomicBool::new(true);
        let clock = TestClock::new();
        let (states, tokens) = create_data();

        let updater = TokenUpdater::new(&states, &tokens, rx, tx.clone(), &is_running, &clock);

        clock.set(1);
        updater.on_command(ManagerCommand::ScheduledRefresh(0, clock.now()));
        {
            let state = states[0].lock().unwrap();
            assert_eq!("token", state.token_id);
            assert_eq!(vec![Scope::new("scope")], state.scopes);
            assert_eq!(1, state.last_touched);
            assert_eq!(751, state.refresh_at);
            assert_eq!(851, state.warn_at);
            assert_eq!(1001, state.expires_at);
            assert_eq!(None, state.last_notification_at);
            assert_eq!(true, state.is_initialized);
            assert_eq!(false, state.is_error);
            assert_eq!(0, state.index);
        }
        assert_eq!(
            "0",
            &tokens
                .get("token")
                .unwrap()
                .1
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .0
        );
    }

    #[test]
    fn updater_workflow() {
        let (tx, rx) = mpsc::channel();
        let is_running = AtomicBool::new(true);
        let clock = TestClock::new();
        let (states, tokens) = create_data();

        let updater = TokenUpdater::new(&states, &tokens, rx, tx.clone(), &is_running, &clock);

        clock.set(0);
        updater.on_command(ManagerCommand::ScheduledRefresh(0, clock.now()));
        {
            let state = states[0].lock().unwrap();
            assert_eq!("token", state.token_id);
            assert_eq!(vec![Scope::new("scope")], state.scopes);
            assert_eq!(0, state.last_touched);
            assert_eq!(750, state.refresh_at);
            assert_eq!(850, state.warn_at);
            assert_eq!(1000, state.expires_at);
            assert_eq!(None, state.last_notification_at);
            assert_eq!(true, state.is_initialized);
            assert_eq!(false, state.is_error);
            assert_eq!(0, state.index);
        }
        assert_eq!(
            "0",
            &tokens
                .get("token")
                .unwrap()
                .1
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .0
        );

        // Regular refresh
        clock.set(750);
        updater.on_command(ManagerCommand::ScheduledRefresh(0, clock.now()));
        {
            let state = states[0].lock().unwrap();
            assert_eq!("token", state.token_id);
            assert_eq!(vec![Scope::new("scope")], state.scopes);
            assert_eq!(750, state.last_touched);
            assert_eq!(1500, state.refresh_at);
            assert_eq!(1600, state.warn_at);
            assert_eq!(1750, state.expires_at);
            assert_eq!(None, state.last_notification_at);
            assert_eq!(true, state.is_initialized);
            assert_eq!(false, state.is_error);
            assert_eq!(0, state.index);
        }
        assert_eq!(
            "1",
            &tokens
                .get("token")
                .unwrap()
                .1
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .0
        );

        // Second regular refresh with same timestamp as before should not trigger
        clock.set(750);
        updater.on_command(ManagerCommand::ScheduledRefresh(0, clock.now()));
        {
            let state = states[0].lock().unwrap();
            assert_eq!(750, state.last_touched);
            assert_eq!(1500, state.refresh_at);
            assert_eq!(1600, state.warn_at);
            assert_eq!(1750, state.expires_at);
            assert_eq!(true, state.is_initialized);
            assert_eq!(false, state.is_error);
        }
        assert_eq!(
            "1",
            &tokens
                .get("token")
                .unwrap()
                .1
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .0
        );

        // Forced Refresh
        clock.set(800);
        updater.on_command(ManagerCommand::ForceRefresh("token", clock.now()));
        {
            let state = states[0].lock().unwrap();
            assert_eq!(800, state.last_touched);
            assert_eq!(1550, state.refresh_at);
            assert_eq!(1650, state.warn_at);
            assert_eq!(1800, state.expires_at);
            assert_eq!(true, state.is_initialized);
            assert_eq!(false, state.is_error);
        }
        assert_eq!(
            "2",
            &tokens
                .get("token")
                .unwrap()
                .1
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .0
        );

        // Refresh on error
        {
            let mut state = states[0].lock().unwrap();
            state.is_error = true;
        }
        clock.set(801);
        updater.on_command(ManagerCommand::RefreshOnError(0, clock.now()));
        {
            let state = states[0].lock().unwrap();
            assert_eq!("token", state.token_id);
            assert_eq!(801, state.last_touched);
            assert_eq!(1551, state.refresh_at);
            assert_eq!(1651, state.warn_at);
            assert_eq!(1801, state.expires_at);
            assert_eq!(true, state.is_initialized);
            assert_eq!(false, state.is_error);
        }
        assert_eq!(
            "3",
            &tokens
                .get("token")
                .unwrap()
                .1
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .0
        );

        // Regular refresh on error
        {
            let mut state = states[0].lock().unwrap();
            state.is_error = true;
        }
        clock.set(802);
        updater.on_command(ManagerCommand::ScheduledRefresh(0, clock.now()));
        {
            let state = states[0].lock().unwrap();
            assert_eq!("token", state.token_id);
            assert_eq!(802, state.last_touched);
            assert_eq!(1552, state.refresh_at);
            assert_eq!(1652, state.warn_at);
            assert_eq!(1802, state.expires_at);
            assert_eq!(true, state.is_initialized);
            assert_eq!(false, state.is_error);
        }
        assert_eq!(
            "4",
            &tokens
                .get("token")
                .unwrap()
                .1
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .0
        );

        // Simultaneous refresh on error does nothing
        updater.on_command(ManagerCommand::RefreshOnError(0, clock.now()));
        {
            let state = states[0].lock().unwrap();
            assert_eq!("token", state.token_id);
            assert_eq!(802, state.last_touched);
            assert_eq!(1552, state.refresh_at);
            assert_eq!(1652, state.warn_at);
            assert_eq!(1802, state.expires_at);
            assert_eq!(true, state.is_initialized);
            assert_eq!(false, state.is_error);
        }
        assert_eq!(
            "4",
            &tokens
                .get("token")
                .unwrap()
                .1
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .0
        );
    }
}
