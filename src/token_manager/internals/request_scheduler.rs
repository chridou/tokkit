use super::*;
use std::sync::mpsc;
use std::cmp;

pub struct RefreshScheduler<'a, T: 'a> {
    rows: &'a [Mutex<TokenRow<T>>],
    sender: &'a mpsc::Sender<ManagerCommand<T>>,
    /// The time that must at least elapse between 2 notifications
    min_notification_interval_ms: u64,
    /// The number of ms a cycle should take at max.
    max_cycle_dur_ms: u64,
    is_running: &'a AtomicBool,
    clock: &'a Clock,
}

impl<'a, T: Eq + Ord + Send + Clone + Display> RefreshScheduler<'a, T> {
    pub fn new(
        rows: &'a [Mutex<TokenRow<T>>],
        sender: &'a mpsc::Sender<ManagerCommand<T>>,
        max_cycle_dur_ms: u64,
        min_notification_interval_ms: u64,
        is_running: &'a AtomicBool,
        clock: &'a Clock,
    ) -> Self {
        RefreshScheduler {
            rows,
            sender,
            min_notification_interval_ms,
            max_cycle_dur_ms,
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

            let next_scheduled_at = self.do_a_scheduling_round();

            let elapsed = elapsed_millis_from(start, self.clock);
            let sleep_dur_ms_regular = minus_millis(self.max_cycle_dur_ms, elapsed);
            let sleep_next_scheduled_ms = diff_millis(self.clock.now(), next_scheduled_at);
            let sleep_dur_ms = cmp::min(sleep_dur_ms_regular, sleep_next_scheduled_ms);
            if sleep_dur_ms > 0 {
                let sleep_dur = Duration::from_millis(sleep_dur_ms);
                thread::sleep(sleep_dur);
            }
        }
        info!("Scheduler loop exited.")
    }

    fn do_a_scheduling_round(&self) -> EpochMillis {
        let mut next_at = u64::max_value();
        let mut is_refresh_pending = false;
        for (idx, row) in self.rows.iter().enumerate() {
            let row = &mut *row.lock().unwrap();
            if row.scheduled_for <= self.clock.now() {
                is_refresh_pending = true;
                row.token_state = match row.token_state {
                    TokenState::Uninitialized => {
                        if let Err(err) = self.sender.send(ManagerCommand::ScheduledRefresh(
                            idx,
                            self.clock.now(),
                        ))
                        {
                            error!("Could not send initial refresh command: {}", err);
                            break;
                        }
                        TokenState::Initializing
                    }
                    TokenState::Initializing => TokenState::Initializing,
                    TokenState::Ok => {
                        if let Err(err) = self.sender.send(ManagerCommand::ScheduledRefresh(
                            idx,
                            self.clock.now(),
                        ))
                        {
                            error!("Could not send regular refresh command: {}", err);
                            break;
                        }
                        TokenState::OkPending
                    }
                    TokenState::OkPending => TokenState::OkPending,
                    TokenState::Error => {
                        if let Err(err) = self.sender.send(ManagerCommand::RefreshOnError(
                            idx,
                            self.clock.now(),
                        ))
                        {
                            error!("Could not send refresh on error command: {}", err);
                            break;
                        }
                        TokenState::ErrorPending
                    }
                    TokenState::ErrorPending => TokenState::ErrorPending,
                };
            } else {
                next_at = cmp::min(next_at, row.scheduled_for);
                is_refresh_pending = is_refresh_pending || row.token_state.is_refresh_pending();
            }
            self.check_notifications(row);
        }
        if is_refresh_pending {
            self.clock.now() + 50
        } else {
            next_at
        }
    }

    fn check_notifications(&self, row: &mut TokenRow<T>) {
        let now = self.clock.now();
        let notify = if let Some(last_notified) = row.last_notification_at {
            minus_millis(now, last_notified) >= self.min_notification_interval_ms
        } else {
            true
        };
        if notify {
            let notified = match row.token_state {
                TokenState::Error | TokenState::ErrorPending => {
                    warn!("Token '{}' is in error row.", row.token_id);
                    true
                }
                TokenState::Ok | TokenState::OkPending => {
                    if row.expires_at <= now {
                        warn!(
                            "Token '{}' expired {:.2} minutes ago.",
                            row.token_id,
                            (now - row.expires_at) as f64 / 60_000.0
                        );
                        true
                    } else if row.warn_at <= now {
                        warn!(
                            "Token '{}' expires in {:.2} minutes.",
                            row.token_id,
                            (row.expires_at - now) as f64 / 60_000.0
                        );
                        true
                    } else {
                        false
                    }
                }
                TokenState::Uninitialized |
                TokenState::Initializing => false,
            };
            if notified {
                row.last_notification_at = Some(now);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::cell::Cell;
    use std::rc::Rc;
    use std::sync::mpsc;
    use std::sync::atomic::AtomicBool;
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

        pub fn set(&self, ms: u64) {
            self.time.set(ms);
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> u64 {
            self.time.get()
        }
    }

    struct DummyTokenProvider;

    impl AccessTokenProvider for DummyTokenProvider {
        fn request_access_token(&self, _scopes: &[Scope]) -> AccessTokenProviderResult {
            unimplemented!()
        }
    }

    fn create_token_rows() -> Vec<Mutex<TokenRow<&'static str>>> {
        let mut groups = Vec::default();
        groups.push(
            ManagedTokenGroupBuilder::single_token(
                "token",
                vec![Scope::new("scope")],
                DummyTokenProvider,
            ).build()
                .unwrap(),
        );
        create_rows(groups, 0)
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
        let rows = create_token_rows();
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
    fn scheduler_sends_initial_refresh_while_nothing_happens() {
        let (tx, rx) = mpsc::channel();
        let is_running = AtomicBool::new(true);
        let clock = TestClock::new();
        let rows = create_token_rows();

        let scheduler = RefreshScheduler::new(&rows, &tx, 0, 1000, &is_running, &clock);

        {
            let row = rows[0].lock().unwrap();
            assert_eq!(0, row.refresh_at);
            assert_eq!(0, row.warn_at);
            assert_eq!(0, row.expires_at);
            assert_eq!(0, row.scheduled_for);
            assert_eq!(TokenState::Uninitialized, row.token_state);
            assert_eq!(None, row.last_notification_at);
        }

        clock.set(100);
        scheduler.do_a_scheduling_round();

        let msg = rx.recv().unwrap();
        assert_eq!(ManagerCommand::ScheduledRefresh(0, 100), msg);
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(0, row.refresh_at);
            assert_eq!(0, row.warn_at);
            assert_eq!(0, row.expires_at);
            assert_eq!(0, row.scheduled_for);
            assert_eq!(TokenState::Initializing, row.token_state);
            assert_eq!(None, row.last_notification_at);
        }

        clock.inc(1000);
        scheduler.do_a_scheduling_round();

        let msg = rx.try_recv();
        assert_eq!(true, msg.is_err());
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(0, row.refresh_at);
            assert_eq!(0, row.warn_at);
            assert_eq!(0, row.expires_at);
            assert_eq!(0, row.scheduled_for);
            assert_eq!(TokenState::Initializing, row.token_state);
            assert_eq!(None, row.last_notification_at);
        }
    }


    #[test]
    fn scheduler_workflow() {
        let (tx, rx) = mpsc::channel();
        let is_running = AtomicBool::new(true);
        let clock = TestClock::new();
        let rows = create_token_rows();

        let scheduler = RefreshScheduler::new(&rows, &tx, 0, 1000, &is_running, &clock);

        {
            let row = rows[0].lock().unwrap();
            assert_eq!(0, row.refresh_at);
            assert_eq!(0, row.warn_at);
            assert_eq!(0, row.expires_at);
            assert_eq!(0, row.scheduled_for);
            assert_eq!(TokenState::Uninitialized, row.token_state);
            assert_eq!(None, row.last_notification_at);
        }

        clock.set(100);
        scheduler.do_a_scheduling_round();

        let msg = rx.try_recv().unwrap();
        assert_eq!(ManagerCommand::ScheduledRefresh(0, 100), msg);
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(0, row.refresh_at);
            assert_eq!(0, row.warn_at);
            assert_eq!(0, row.expires_at);
            assert_eq!(0, row.scheduled_for);
            assert_eq!(TokenState::Initializing, row.token_state);
            assert_eq!(None, row.last_notification_at);
        }

        // The token comes in at 1000
        clock.set(1000);
        {
            let mut row = rows[0].lock().unwrap();
            row.refresh_at = clock.now() + 7500;
            row.warn_at = clock.now() + 8500;
            row.expires_at = clock.now() + 10000;
            row.scheduled_for = clock.now() + 7500;
            row.token_state = TokenState::Ok;
        }
        scheduler.do_a_scheduling_round();

        let msg = rx.try_recv();
        assert_eq!(true, msg.is_err());
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(8500, row.refresh_at);
            assert_eq!(9500, row.warn_at);
            assert_eq!(11000, row.expires_at);
            assert_eq!(8500, row.scheduled_for);
            assert_eq!(TokenState::Ok, row.token_state);
            assert_eq!(None, row.last_notification_at);
        }

        // at 1001 nothing should happen
        clock.set(1001);
        scheduler.do_a_scheduling_round();

        let msg = rx.try_recv();
        assert_eq!(true, msg.is_err());
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(8500, row.refresh_at);
            assert_eq!(9500, row.warn_at);
            assert_eq!(11000, row.expires_at);
            assert_eq!(8500, row.scheduled_for);
            assert_eq!(TokenState::Ok, row.token_state);
            assert_eq!(None, row.last_notification_at);
        }


        // at 8499 still nothing should happen
        clock.set(8499);
        scheduler.do_a_scheduling_round();

        let msg = rx.try_recv();
        assert_eq!(true, msg.is_err());
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(8500, row.refresh_at);
            assert_eq!(9500, row.warn_at);
            assert_eq!(11000, row.expires_at);
            assert_eq!(8500, row.scheduled_for);
            assert_eq!(TokenState::Ok, row.token_state);
            assert_eq!(None, row.last_notification_at);
        }

        // at 8500 a refresh request should be sent
        clock.set(8500);
        scheduler.do_a_scheduling_round();

        let msg = rx.try_recv().unwrap();
        assert_eq!(ManagerCommand::ScheduledRefresh(0, 8500), msg);
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(8500, row.refresh_at);
            assert_eq!(9500, row.warn_at);
            assert_eq!(11000, row.expires_at);
            assert_eq!(8500, row.scheduled_for);
            assert_eq!(TokenState::OkPending, row.token_state);
            assert_eq!(None, row.last_notification_at);
        }

        // at 9499 nothing should happen
        clock.set(9499);
        scheduler.do_a_scheduling_round();

        let msg = rx.try_recv();
        assert_eq!(true, msg.is_err());
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(8500, row.refresh_at);
            assert_eq!(9500, row.warn_at);
            assert_eq!(11000, row.expires_at);
            assert_eq!(8500, row.scheduled_for);
            assert_eq!(TokenState::OkPending, row.token_state);
            assert_eq!(None, row.last_notification_at);
        }

        // at 9500 a notification should have taken place
        clock.set(9500);
        scheduler.do_a_scheduling_round();

        let msg = rx.try_recv();
        assert_eq!(true, msg.is_err());
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(8500, row.refresh_at);
            assert_eq!(9500, row.warn_at);
            assert_eq!(11000, row.expires_at);
            assert_eq!(8500, row.scheduled_for);
            assert_eq!(TokenState::OkPending, row.token_state);
            assert_eq!(Some(9500), row.last_notification_at);
        }

        // at 10499 nothing should happen
        clock.set(10499);
        scheduler.do_a_scheduling_round();

        let msg = rx.try_recv();
        assert_eq!(true, msg.is_err());
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(8500, row.refresh_at);
            assert_eq!(9500, row.warn_at);
            assert_eq!(11000, row.expires_at);
            assert_eq!(8500, row.scheduled_for);
            assert_eq!(TokenState::OkPending, row.token_state);
            assert_eq!(Some(9500), row.last_notification_at);
        }

        // At 10500 the next notification should have taken place
        clock.set(10500);
        scheduler.do_a_scheduling_round();

        let msg = rx.try_recv();
        assert_eq!(true, msg.is_err());
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(8500, row.refresh_at);
            assert_eq!(9500, row.warn_at);
            assert_eq!(11000, row.expires_at);
            assert_eq!(8500, row.scheduled_for);
            assert_eq!(TokenState::OkPending, row.token_state);
            assert_eq!(Some(10500), row.last_notification_at);
        }


        // At 10600 the token comes in
        clock.set(10600);
        {
            let mut row = rows[0].lock().unwrap();
            row.refresh_at = clock.now() + 7500;
            row.warn_at = clock.now() + 8500;
            row.expires_at = clock.now() + 10000;
            row.scheduled_for = clock.now() + 7500;
            row.token_state = TokenState::Ok;
        }
        scheduler.do_a_scheduling_round();

        // At 11000 nothing should happen
        let msg = rx.try_recv();
        assert_eq!(true, msg.is_err());
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(10600 + 7500, row.refresh_at);
            assert_eq!(10600 + 8500, row.warn_at);
            assert_eq!(10600 + 10000, row.expires_at);
            assert_eq!(10600 + 7500, row.scheduled_for);
            assert_eq!(TokenState::Ok, row.token_state);
            assert_eq!(Some(10500), row.last_notification_at);
        }


        // at 18100 the next token is requested
        clock.set(18100);
        scheduler.do_a_scheduling_round();

        let msg = rx.try_recv().unwrap();
        assert_eq!(ManagerCommand::ScheduledRefresh(0, 18100), msg);
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(10600 + 7500, row.refresh_at);
            assert_eq!(10600 + 8500, row.warn_at);
            assert_eq!(10600 + 10000, row.expires_at);
            assert_eq!(10600 + 7500, row.scheduled_for);
            assert_eq!(TokenState::OkPending, row.token_state);
            assert_eq!(Some(10500), row.last_notification_at);
        }

        // at 20000 the token enters error state
        // and only a notification takes place
        clock.set(20000);
        {
            let mut row = rows[0].lock().unwrap();
            row.refresh_at = clock.now();
            row.warn_at = clock.now();
            row.expires_at = clock.now();
            row.scheduled_for = clock.now() + 100;
            row.token_state = TokenState::Error;
        }
        scheduler.do_a_scheduling_round();

        let msg = rx.try_recv();
        assert_eq!(true, msg.is_err());
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(20000, row.refresh_at);
            assert_eq!(20000, row.warn_at);
            assert_eq!(20000, row.expires_at);
            assert_eq!(20100, row.scheduled_for);
            assert_eq!(TokenState::Error, row.token_state);
            assert_eq!(Some(20000), row.last_notification_at);
        }

        // at 20100 a request for a refresh on error is scheduled
        clock.set(20100);
        scheduler.do_a_scheduling_round();

        let msg = rx.try_recv().unwrap();
        assert_eq!(ManagerCommand::RefreshOnError(0, 20100), msg);
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(20000, row.refresh_at);
            assert_eq!(20000, row.warn_at);
            assert_eq!(20000, row.expires_at);
            assert_eq!(20100, row.scheduled_for);
            assert_eq!(TokenState::ErrorPending, row.token_state);
            assert_eq!(Some(20000), row.last_notification_at);
        }

        // at 21000 the error is resolved and nothing should happen
        clock.set(21000);
        {
            let mut row = rows[0].lock().unwrap();
            row.refresh_at = clock.now() + 7500;
            row.warn_at = clock.now() + 8500;
            row.expires_at = clock.now() + 10000;
            row.scheduled_for = clock.now() + 7500;
            row.token_state = TokenState::Ok;
        }
        scheduler.do_a_scheduling_round();

        let msg = rx.try_recv();
        assert_eq!(true, msg.is_err());
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(28500, row.refresh_at);
            assert_eq!(29500, row.warn_at);
            assert_eq!(31000, row.expires_at);
            assert_eq!(28500, row.scheduled_for);
            assert_eq!(TokenState::Ok, row.token_state);
            assert_eq!(Some(20000), row.last_notification_at);
        }

        // at 28500 a refresh should be sent..
        clock.set(28500);
        scheduler.do_a_scheduling_round();

        let msg = rx.try_recv().unwrap();
        assert_eq!(ManagerCommand::ScheduledRefresh(0, 28500), msg);
        {
            let row = rows[0].lock().unwrap();
            assert_eq!(28500, row.refresh_at);
            assert_eq!(29500, row.warn_at);
            assert_eq!(31000, row.expires_at);
            assert_eq!(28500, row.scheduled_for);
            assert_eq!(TokenState::OkPending, row.token_state);
            assert_eq!(Some(20000), row.last_notification_at);
        }

        // and so on .....
    }
}
