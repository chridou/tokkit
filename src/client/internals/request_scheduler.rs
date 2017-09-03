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
    pub fn start(
        states: &'a [Mutex<TokenState<T>>],
        sender: &'a mpsc::Sender<ManagerCommand<T>>,
        min_cycle_dur_ms: u64,
        min_notification_interval_ms: u64,
        is_running: &'a AtomicBool,
        clock: &'a Clock,
    ) {
        let scheduler = RefreshScheduler {
            states,
            sender,
            min_notification_interval_ms,
            min_cycle_dur_ms,
            is_running,
            clock,
        };
        scheduler.run_scheduler_loop();
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
    use std::cell::Cell;
    use client::*;
    use super::*;

    struct DummyTokenService {
        counter: Cell<u32>,
    }

    impl DummyTokenService {
        pub fn new() -> Self {
            DummyTokenService { counter: Cell::new(0) }
        }
    }

    impl TokenService for DummyTokenService {
        fn get_token(&self, scopes: &[Scope]) -> TokenServiceResult {
            self.counter.set(self.counter.get()+ 1);
            Ok(TokenServiceResponse {
                token: AccessToken::new(self.counter.get().to_string()),
                expires_in: Duration::from_secs(1),
            })
        }
    }

    fn create_token_states() -> Vec<Mutex<TokenState<&'static str>>> {
        let mut groups = Vec::default();
        groups.push(ManagedTokenBuilder::easy("token", Vec::new(), DummyTokenService::new())
        .build().unwrap());
        create_states(groups, 0)
    }

    #[test]
    fn test() {
        let states = create_token_states();
    }
}
