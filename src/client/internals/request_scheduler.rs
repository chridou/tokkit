use super::*;
use std::sync::mpsc;

pub struct RefreshScheduler<'a, T: 'a> {
    states: &'a [Mutex<TokenState<T>>],
    sender: &'a mpsc::Sender<ManagerCommand<T>>,
    /// The time that must at least elapse between 2 notifications
    min_notification_interval_ms: u64,
    /// The number of ms a cycle must at least take.
    min_cycle_dur_ms: u64,
    is_running: &'a AtomicBool,
    clock: &'a Clock,
}

impl<'a, T: Eq + Ord + Send + Clone + Display> RefreshScheduler<'a, T> {
    pub fn new(
        states: &'a [Mutex<TokenState<T>>],
        sender: &'a mpsc::Sender<ManagerCommand<T>>,
        min_cycle_dur_ms: u64,
        min_notification_interval_ms: u64,
        is_running: &'a AtomicBool,
        clock: &'a Clock,
    ) -> Self {
        RefreshScheduler {
            states,
            sender,
            min_notification_interval_ms,
            min_cycle_dur_ms,
            is_running,
            clock,
        }
    }

    pub fn start(&self) {
        self.run_scheduler_loop();
    }

    fn run_scheduler_loop(&self) {
        debug!("Starting scheduler loop");
        while self.is_running.load(Ordering::Relaxed) {
            let start = self.clock.now();

            self.do_a_scheduling_round();

            let elapsed = elapsed_millis_from(start, self.clock);
            let sleep_dur_ms = minus_millis(self.min_cycle_dur_ms, elapsed);
            if sleep_dur_ms > 0 {
                let sleep_dur = Duration::from_millis(sleep_dur_ms);
                thread::sleep(sleep_dur);
            }
        }
        info!("Scheduler loop exited.")
    }

    fn do_a_scheduling_round(&self) {
        for (idx, state) in self.states.iter().enumerate() {
            let state = &mut *state.lock().unwrap();
            if state.refresh_at <= self.clock.now() {

                if let Err(err) = self.sender.send(ManagerCommand::ScheduledRefresh(
                    idx,
                    self.clock.now(),
                ))
                {
                    error!("Could not send refresh command: {}", err);
                    break;
                };

                if state.is_initialized {
                    self.check_notifications(state);
                }
            }
        }
    }

    fn check_notifications(&self, state: &mut TokenState<T>) {
        let now = self.clock.now();
        let notify = if let Some(last_notified) = state.last_notification_at {
            now - last_notified >= self.min_notification_interval_ms
        } else {
            true
        };
        if notify {
            let notified = if state.is_error {
                warn!("Token '{}' is in error state.", state.token_id);
                true
            } else if state.expires_at < now {
                warn!(
                    "Token '{}' expired {:.2} minutes ago.",
                    state.token_id,
                    (now - state.expires_at) as f64 / 60_000.0
                );
                true
            } else if state.warn_at < now {
                warn!(
                    "Token '{}' expires in {:.2} minutes.",
                    state.token_id,
                    (state.expires_at - now) as f64 / 60_000.0
                );
                true
            } else {
                false
            };
            if notified {
                state.last_notification_at = Some(now);
            }
        }
    }
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
            TestClock { time: Rc::new(Cell::new(0)) }
        }

        pub fn inc(&self, by_ms: u64) {
            let past = self.time.get();
            self.time.set(past + by_ms);
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> u64 {
            self.time.get()
        }
    }

    struct DummyTokenService {
        counter: Arc<Mutex<u32>>,
    }

    impl DummyTokenService {
        pub fn new() -> Self {
            DummyTokenService { counter: Arc::new(Mutex::new(0)) }
        }
    }

    impl TokenService for DummyTokenService {
        fn get_token(&self, scopes: &[Scope]) -> TokenServiceResult {
            let c: &mut u32 = &mut *self.counter.lock().unwrap();
            let res = Ok(TokenServiceResponse {
                token: AccessToken::new(c.to_string()),
                expires_in: Duration::from_secs(1),
            });
            *c += 1;
            res
        }
    }

    fn create_token_states() -> Vec<Mutex<TokenState<&'static str>>> {
        let mut groups = Vec::default();
        groups.push(
            ManagedTokenGroupBuilder::single_token(
                "token",
                vec![Scope::new("scope")],
                DummyTokenService::new(),
            ).build()
                .unwrap(),
        );
        create_states(groups, 0)
    }

    #[test]
    fn clock_test() {
        let clock1 = TestClock::new();
        let clock2 = clock1.clone();
        clock1.inc(100);
        assert_eq!(100, clock2.now());
    }

    #[test]
    fn iniitial_state_is_correct() {
        let states = create_token_states();
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
    fn scheduler_sends_initial_refresh() {
        let (tx, rx) = mpsc::channel();
        let is_running = AtomicBool::new(true);
        let clock = TestClock::new();
        let states = create_token_states();

        let scheduler = RefreshScheduler::new(&states, &tx, 0, 1000, &is_running, &clock);

        scheduler.do_a_scheduling_round();

        {
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

        let msg = rx.recv().unwrap();
        assert_eq!(ManagerCommand::ScheduledRefresh(0, 0), msg);

        clock.inc(1000);

        scheduler.do_a_scheduling_round();

        {
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

        let msg = rx.recv().unwrap();
        assert_eq!(ManagerCommand::ScheduledRefresh(0, 1000), msg);
    }
}
