use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use client::tokenservice::TokenService;
use super::*;

pub fn initialize(groups: Vec<ManagedTokenGroup>) -> Arc<Inner> {
    let mut states = Vec::new();
    let mut tokens: BTreeMap<TokenName, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)> =
        Default::default();
    let mut idx = 0;
    for group in groups {
        for managed_token in group.managed_tokens {
            states.push(Mutex::new(ManagedTokenState {
                name: managed_token.name.clone(),
                scopes: managed_token.scopes,
                refresh_threshold: group.refresh_threshold,
                warning_threshold: group.warning_threshold,
                refresh_at: Instant::now(),
                warn_at: Instant::now(),
                expires_at: Instant::now(),
                token_service: group.token_service.clone(),
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
    let is_running = AtomicBool::new(true);

    let inner = Arc::new(Inner { tokens, is_running });

    start_manager_loop(states, inner.clone());

    inner.clone()
}

pub struct Inner {
    pub tokens: BTreeMap<TokenName, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)>,
    pub is_running: AtomicBool,
}

impl ProvidesTokens for Inner {
    fn get_token(&self, name: &TokenName) -> Result<AccessToken> {
        match self.tokens.get(&name) {
            Some(&(_, ref guard)) => {
                match &*guard.lock().unwrap() {
                    &Ok(ref token) => Ok(token.clone()),
                    &Err(ref err) => bail!(err.clone()),
                }
            }
            None => bail!(ErrorKind::NoToken(name.clone())),
        }
    }
}



struct ManagedTokenState {
    name: TokenName,
    scopes: Vec<Scope>,
    refresh_threshold: f32,
    warning_threshold: f32,
    refresh_at: Instant,
    warn_at: Instant,
    expires_at: Instant,
    token_service: Arc<TokenService + Send + Sync + 'static>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.is_running.store(false, Ordering::Relaxed);
    }
}

fn start_manager_loop(states: Vec<Mutex<ManagedTokenState>>, inner: Arc<Inner>) {
    let states1 = Arc::new(states);
    let states2 = states1.clone();
    let inner1 = inner.clone();
    thread::spawn(move || run_scheduler_loop(&*states1, &inner1.is_running));
    thread::spawn(move || run_updater_loop(&*states2, &inner.tokens));
}

enum ManagerCommand {
    ScheduledRefresh(usize),
    ForceRefresh(TokenName),
    Stop,
}

fn run_scheduler_loop(states: &[Mutex<ManagedTokenState>], is_running: &AtomicBool) {
    while is_running.load(Ordering::Relaxed) {}
}

fn run_updater_loop(
    states: &[Mutex<ManagedTokenState>],
    tokens: &BTreeMap<TokenName, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)>,
) {
    loop {}
}

fn refresh_token(state: &Mutex<ManagedTokenState>, token: &Mutex<StdResult<AccessToken, ErrorKind>>) {

}
