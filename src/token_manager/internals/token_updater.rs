use backoff::{Error as BError, ExponentialBackoff, Operation};
use std::collections::BTreeMap;
use std::sync::mpsc;
use std::sync::Mutex;

use super::*;

pub struct TokenUpdater<'a, T: 'a> {
    rows: &'a [Mutex<TokenRow<T>>],
    tokens: &'a BTreeMap<T, (usize, Mutex<StdResult<AccessToken, TokenErrorKind>>)>,
    receiver: mpsc::Receiver<ManagerCommand<T>>,
    is_running: &'a AtomicBool,
    clock: &'a dyn Clock,
}

impl<'a, T: Eq + Ord + Send + Clone + Display> TokenUpdater<'a, T> {
    pub fn new(
        rows: &'a [Mutex<TokenRow<T>>],
        tokens: &'a BTreeMap<T, (usize, Mutex<StdResult<AccessToken, TokenErrorKind>>)>,
        receiver: mpsc::Receiver<ManagerCommand<T>>,
        is_running: &'a AtomicBool,
        clock: &'a dyn Clock,
    ) -> Self {
        TokenUpdater {
            rows,
            tokens,
            receiver,
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
                let row = &self.rows[idx];
                let token_id = &row.lock().unwrap().token_id.clone();
                debug!("Scheduled refresh for token '{}'", token_id);
                let &(_, ref token) = self.tokens.get(token_id).unwrap();
                self.refresh_token(row, token, timestamp);
                true
            }
            ManagerCommand::ForceRefresh(token_id, timestamp) => {
                info!("Forced refresh for token '{}'", token_id);
                let &(idx, ref token) = self.tokens.get(&token_id).unwrap();
                let token_state = &self.rows[idx];
                self.refresh_token(token_state, token, timestamp);
                true
            }
            ManagerCommand::RefreshOnError(idx, timestamp) => {
                let row = &self.rows[idx];
                let token_id = &row.lock().unwrap().token_id.clone();
                info!("Refresh on error for token '{}'", token_id);
                let &(_, ref token) = self.tokens.get(token_id).unwrap();
                self.refresh_token(row, token, timestamp);
                true
            }
        }
    }

    fn refresh_token(
        &self,
        row: &Mutex<TokenRow<T>>,
        token: &Mutex<StdResult<AccessToken, TokenErrorKind>>,
        command_timestamp: u64,
    ) {
        let row: &mut TokenRow<T> = &mut *row.lock().unwrap();
        if row.last_touched <= command_timestamp || row.token_state.is_uninitialized() {
            match call_token_service(&*row.token_provider, &row.scopes) {
                Ok(rsp) => {
                    debug!("Update received token data");
                    update_token_ok(rsp, row, token, self.clock);
                }
                Err(err) => self.handle_error(err, row, token),
            }
        } else {
            info!("Skipping refresh because the command was too old.");
        }
    }

    fn handle_error(
        &self,
        err: AccessTokenProviderError,
        row: &mut TokenRow<T>,
        token: &Mutex<StdResult<AccessToken, TokenErrorKind>>,
    ) {
        match row.token_state {
            TokenState::Uninitialized | TokenState::Initializing => {
                error!(
                    "Received an error for token '{}' which is not even initialized! \
                     Error: {}",
                    row.token_id, err
                );
                update_token_err(err, row, token, self.clock);
            }
            TokenState::Ok | TokenState::OkPending => if row.expires_at <= self.clock.now() {
                error!(
                    "Received an error for token '{}' and the token has already expired! \
                     Error: {}",
                    row.token_id, err
                );
                update_token_err(err, row, token, self.clock);
            } else {
                error!(
                    "Received an error for token '{}'. Will not update the \
                     token because it is still valid. \
                     Error: {}",
                    row.token_id, err
                );
            },
            TokenState::Error | TokenState::ErrorPending => {
                error!(
                    "Received an error for token '{}' and the token is already \
                     in error token_state! \
                     Error: {}",
                    row.token_id, err
                );
                update_token_err(err, row, token, self.clock);
            }
        }
    }
}

fn update_token_ok<T: Display>(
    rsp: AuthorizationServerResponse,
    row: &mut TokenRow<T>,
    token: &Mutex<StdResult<AccessToken, TokenErrorKind>>,
    clock: &dyn Clock,
) {
    *token.lock().unwrap() = Ok(rsp.access_token);
    let now = clock.now();
    let expires_in_ms = millis_from_duration(rsp.expires_in);
    let old_last_touched = row.last_touched;
    row.last_touched = now;
    row.expires_at = now + expires_in_ms;
    row.refresh_at = now + (expires_in_ms as f32 * row.refresh_threshold) as u64;
    row.scheduled_for = row.refresh_at;
    row.token_state = TokenState::Ok;
    row.warn_at = now + (expires_in_ms as f32 * row.warning_threshold) as u64;
    info!(
        "Refreshed token '{}' after {:.3} minutes. New token will expire in {:.3} minutes. \
         Refresh in {:.3} minutes.",
        row.token_id,
        diff_millis(old_last_touched, now) as f64 / (60.0 * 1000.0),
        rsp.expires_in.as_secs() as f64 / 60.0,
        diff_millis(now, row.refresh_at) as f64 / (60.0 * 1000.0),
    );
}

fn update_token_err<T: Display>(
    err: AccessTokenProviderError,
    row: &mut TokenRow<T>,
    token: &Mutex<StdResult<AccessToken, TokenErrorKind>>,
    clock: &dyn Clock,
) {
    *token.lock().unwrap() = Err(TokenErrorKind::AccessTokenProvider(err.to_string()));
    let now = clock.now();
    row.last_touched = now;
    row.expires_at = now;
    row.refresh_at = now;
    row.warn_at = now;
    row.scheduled_for = match row.token_state {
        TokenState::Uninitialized | TokenState::Initializing => now + 100,
        TokenState::Ok | TokenState::OkPending => now + 1_000,
        TokenState::Error | TokenState::ErrorPending => now + 5_000,
    };
    row.token_state = TokenState::Error;
}

fn call_token_service(
    provider: &dyn AccessTokenProvider,
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
                Err(AccessTokenProviderError::BadAuthorizationRequest(err)) => {
                    warn!("Call to token service failed: {:?}", err.error);
                    Err(BError::Permanent(
                        AccessTokenProviderError::BadAuthorizationRequest(err),
                    ))
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
mod refresh_tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use crate::token_manager::AuthorizationServerResponse;

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
        fn request_access_token(&self, _scopes: &[Scope]) -> AccessTokenProviderResult {
            let c: &mut u32 = &mut *self.counter.lock().unwrap();
            let res = Ok(AuthorizationServerResponse {
                access_token: AccessToken::new(c.to_string()),
                expires_in: Duration::from_secs(1),
                refresh_token: None,
            });
            *c += 1;
            res
        }
    }

    fn create_data() -> (
        Vec<Mutex<TokenRow<&'static str>>>,
        BTreeMap<&'static str, (usize, Mutex<StdResult<AccessToken, TokenErrorKind>>)>,
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
        let rows = create_rows(groups, 0);
        (rows, tokens)
    }

    #[test]
    fn clock_test() {
        let clock1 = TestClock::new();
        let clock2 = clock1.clone();
        clock1.inc(100);
        assert_eq!(100, clock2.now());
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn initial_state_is_correct() {
        let (rows, _) = create_data();
        let row = rows[0].lock().unwrap();
        assert_eq!("token", row.token_id);
        assert_eq!(vec![Scope::new("scope")], row.scopes);
        assert_eq!(0.75, row.refresh_threshold);
        assert_eq!(0.85, row.warning_threshold);
        assert_eq!(0, row.refresh_at);
        assert_eq!(0, row.warn_at);
        assert_eq!(0, row.expires_at);
        assert_eq!(0, row.scheduled_for);
        assert_eq!(TokenState::Uninitialized, row.token_state);
        assert_eq!(None, row.last_notification_at);
    }

    #[test]
    fn initializes_token_when_time_did_not_increase() {
        let (_, rx) = mpsc::channel();
        let is_running = AtomicBool::new(true);
        let clock = TestClock::new();
        let (rows, tokens) = create_data();

        let updater = TokenUpdater::new(&rows, &tokens, rx, &is_running, &clock);

        clock.set(0);
        updater.on_command(ManagerCommand::ScheduledRefresh(0, clock.now()));
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(0, row.last_touched);
            assert_eq!(750, row.refresh_at);
            assert_eq!(850, row.warn_at);
            assert_eq!(1000, row.expires_at);
            assert_eq!(TokenState::Ok, row.token_state);
            assert_eq!(None, row.last_notification_at);
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
    fn does_initialize_token_twice_when_time_did_not_increase() {
        let (_, rx) = mpsc::channel();
        let is_running = AtomicBool::new(true);
        let clock = TestClock::new();
        let (rows, tokens) = create_data();

        let updater = TokenUpdater::new(&rows, &tokens, rx, &is_running, &clock);

        clock.set(0);
        updater.on_command(ManagerCommand::ScheduledRefresh(0, clock.now()));
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(0, row.last_touched);
            assert_eq!(750, row.refresh_at);
            assert_eq!(850, row.warn_at);
            assert_eq!(1000, row.expires_at);
            assert_eq!(TokenState::Ok, row.token_state);
            assert_eq!(None, row.last_notification_at);
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
            let row = rows[0].lock().unwrap();
            assert_eq!(0, row.last_touched);
            assert_eq!(750, row.refresh_at);
            assert_eq!(850, row.warn_at);
            assert_eq!(1000, row.expires_at);
            assert_eq!(TokenState::Ok, row.token_state);
            assert_eq!(None, row.last_notification_at);
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
    }

    #[test]
    fn initializes_token_when_time_increased() {
        let (_, rx) = mpsc::channel();
        let is_running = AtomicBool::new(true);
        let clock = TestClock::new();
        let (rows, tokens) = create_data();

        let updater = TokenUpdater::new(&rows, &tokens, rx, &is_running, &clock);

        clock.set(1);
        updater.on_command(ManagerCommand::ScheduledRefresh(0, clock.now()));
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(751, row.refresh_at);
            assert_eq!(851, row.warn_at);
            assert_eq!(1001, row.expires_at);
            assert_eq!(TokenState::Ok, row.token_state);
            assert_eq!(None, row.last_notification_at);
            assert_eq!(1, row.last_touched);
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
    fn refreshes_initilalizing_token() {
        let (_, rx) = mpsc::channel();
        let is_running = AtomicBool::new(true);
        let clock = TestClock::new();
        let (rows, tokens) = create_data();

        let updater = TokenUpdater::new(&rows, &tokens, rx, &is_running, &clock);

        {
            let mut row = rows[0].lock().unwrap();
            row.refresh_at = 0;
            row.warn_at = 0;
            row.expires_at = 0;
            row.scheduled_for = 0;
            row.token_state = TokenState::Initializing;
        }
        clock.set(100);
        updater.on_command(ManagerCommand::ScheduledRefresh(0, 50));
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(100 + 750, row.refresh_at);
            assert_eq!(100 + 850, row.warn_at);
            assert_eq!(100 + 1000, row.expires_at);
            assert_eq!(TokenState::Ok, row.token_state);
            assert_eq!(None, row.last_notification_at);
            assert_eq!(100, row.last_touched);
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
    fn refreshes_ok_pending_token() {
        let (_, rx) = mpsc::channel();
        let is_running = AtomicBool::new(true);
        let clock = TestClock::new();
        let (rows, tokens) = create_data();

        let updater = TokenUpdater::new(&rows, &tokens, rx, &is_running, &clock);

        {
            let mut row = rows[0].lock().unwrap();
            row.refresh_at = 0;
            row.warn_at = 0;
            row.expires_at = 0;
            row.scheduled_for = 0;
            row.token_state = TokenState::OkPending;
        }
        clock.set(100);
        updater.on_command(ManagerCommand::ScheduledRefresh(0, 50));
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(100 + 750, row.refresh_at);
            assert_eq!(100 + 850, row.warn_at);
            assert_eq!(100 + 1000, row.expires_at);
            assert_eq!(TokenState::Ok, row.token_state);
            assert_eq!(None, row.last_notification_at);
            assert_eq!(100, row.last_touched);
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
    fn refreshes_error_token() {
        let (_, rx) = mpsc::channel();
        let is_running = AtomicBool::new(true);
        let clock = TestClock::new();
        let (rows, tokens) = create_data();

        let updater = TokenUpdater::new(&rows, &tokens, rx, &is_running, &clock);

        {
            let mut row = rows[0].lock().unwrap();
            row.refresh_at = 0;
            row.warn_at = 0;
            row.expires_at = 0;
            row.scheduled_for = 0;
            row.token_state = TokenState::Error;
        }
        clock.set(100);
        updater.on_command(ManagerCommand::ScheduledRefresh(0, 50));
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(100 + 750, row.refresh_at);
            assert_eq!(100 + 850, row.warn_at);
            assert_eq!(100 + 1000, row.expires_at);
            assert_eq!(TokenState::Ok, row.token_state);
            assert_eq!(None, row.last_notification_at);
            assert_eq!(100, row.last_touched);
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
    fn refreshes_error_pending_token() {
        let (_, rx) = mpsc::channel();
        let is_running = AtomicBool::new(true);
        let clock = TestClock::new();
        let (rows, tokens) = create_data();

        let updater = TokenUpdater::new(&rows, &tokens, rx, &is_running, &clock);

        {
            let mut row = rows[0].lock().unwrap();
            row.refresh_at = 0;
            row.warn_at = 0;
            row.expires_at = 0;
            row.scheduled_for = 0;
            row.token_state = TokenState::ErrorPending;
        }
        clock.set(100);
        updater.on_command(ManagerCommand::ScheduledRefresh(0, 50));
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(100 + 750, row.refresh_at);
            assert_eq!(100 + 850, row.warn_at);
            assert_eq!(100 + 1000, row.expires_at);
            assert_eq!(TokenState::Ok, row.token_state);
            assert_eq!(None, row.last_notification_at);
            assert_eq!(100, row.last_touched);
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

}
