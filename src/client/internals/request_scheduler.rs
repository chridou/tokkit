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
        if now - state.last_notification_at >= self.min_notification_interval_ms  {
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
                state.last_notification_at = now;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use client::*;
    use super::*;

    struct DummyTokenService;

    impl TokenService for DummyTokenService {
        fn get_token(&self, scopes: &[Scope]) -> TokenServiceResult {
            unimplemented!()
        }
    }

    fn create_token_states() -> Vec<TokenState<&'static str>> {
        let mut states = Vec::default();
        
        states
    }

    #[test]
    fn test() {
        let states = create_token_states();
    }
}
