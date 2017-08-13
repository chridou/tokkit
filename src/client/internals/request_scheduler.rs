use super::*;
use std::sync::mpsc;

pub struct RefreshScheduler<'a> {
    states: &'a [Mutex<TokenState>],
    sender: &'a mpsc::Sender<ManagerCommand>,
    min_notification_interval: Duration,
    min_cycle_dur: Duration,
    is_running: &'a AtomicBool,
    clock: &'a Clock,
}

impl<'a> RefreshScheduler<'a> {
    pub fn start(
        states: &'a [Mutex<TokenState>],
        sender: &'a mpsc::Sender<ManagerCommand>,
        min_cycle_dur: Duration,
        min_notification_interval: Duration,
        is_running: &'a AtomicBool,
        clock: &'a Clock,
    ) {
        let scheduler = RefreshScheduler {
            states,
            sender,
            min_notification_interval,
            min_cycle_dur,
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

            let elapsed = Instant::now() - start;
            let sleep_dur = self.min_cycle_dur.checked_sub(elapsed).unwrap_or(
                Duration::from_secs(
                    0,
                ),
            );
            thread::sleep(sleep_dur);
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

    fn check_notifications(&self, state: &mut TokenState) {
        let now = self.clock.now();
        if now - state.last_notification_at >= self.min_notification_interval {
            let notified = if state.is_error {
                warn!("Token '{}' is in error state.", state.name);
                true
            } else if state.expires_at < now {
                warn!(
                    "Token '{}' expired {:.2} minutes ago.",
                    state.name,
                    (now - state.expires_at).as_secs() as f64 / 60.0
                );
                true
            } else if state.warn_at < now {
                warn!(
                    "Token '{}' expires in {:.2} minutes.",
                    state.name,
                    (state.expires_at - now).as_secs() as f64 / 60.0
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
