use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Instant;
use std::result::Result as StdResult;
use std::fmt;
use {AccessToken, Scope};

pub mod error;
pub mod tokenservice;
mod internals;

use self::error::*;
use self::tokenservice::*;
use self::internals::Inner;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TokenName(pub String);

impl fmt::Display for TokenName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub struct ManagedTokenBuilder {
    pub name: Option<String>,
    pub scopes: Vec<Scope>,
}

impl Default for ManagedTokenBuilder {
    fn default() -> Self {
        ManagedTokenBuilder {
            name: Default::default(),
            scopes: Default::default(),
        }
    }
}

pub struct ManagedToken {
    name: TokenName,
    scopes: Vec<Scope>,
}

pub struct ManagedTokenGroupBuilder<S: TokenService> {
    pub token_service: Option<S>,
    pub managed_tokens: Vec<ManagedToken>,
    pub refresh_threshold: Option<f32>,
    pub warning_threshold: Option<f32>,
}

impl<S: TokenService> Default for ManagedTokenGroupBuilder<S> {
    fn default() -> Self {
        ManagedTokenGroupBuilder {
            token_service: Default::default(),
            managed_tokens: Default::default(),
            refresh_threshold: Default::default(),
            warning_threshold: Default::default(),
        }
    }
}

pub struct ManagedTokenGroup {
    token_service: Arc<TokenService + Send + Sync + 'static>,
    managed_tokens: Vec<ManagedToken>,
    refresh_threshold: f32,
    warning_threshold: f32,
}

pub trait ProvidesTokens {
    fn get_token(&self, name: &TokenName) -> Result<AccessToken>;
    fn refresh(&self, name: &TokenName);
    fn pinned_provider(&self, &TokenName) -> Result<PinnedTokenProvider>;
}

pub trait ProvidesPinnedToken {
    fn get_token(&self) -> Result<AccessToken>;
    fn refresh(&self);
}

#[derive(Clone)]
pub struct TokenProvider {
    inner: Arc<Inner>,
    sender: Sender<internals::ManagerCommand>,
}

impl ProvidesTokens for TokenProvider {
    fn get_token(&self, name: &TokenName) -> Result<AccessToken> {
        match self.inner.tokens.get(&name) {
            Some(&(_, ref guard)) => {
                match &*guard.lock().unwrap() {
                    &Ok(ref token) => Ok(token.clone()),
                    &Err(ref err) => bail!(err.clone()),
                }
            }
            None => bail!(ErrorKind::NoToken(name.clone())),
        }
    }

    fn refresh(&self, name: &TokenName) {
        self.sender
            .send(internals::ManagerCommand::ForceRefresh(
                name.clone(),
                Instant::now(),
            ))
            .unwrap()
    }

    fn pinned_provider(&self, token_name: &TokenName) -> Result<PinnedTokenProvider> {
        match self.inner.tokens.get(token_name) {
            Some(_) => Ok(PinnedTokenProvider {
                token_provider: self.clone(),
                token_name: token_name.clone(),
            }),
            None => Err(ErrorKind::NoToken(token_name.clone()).into()),
        }
    }
}

#[derive(Clone)]
pub struct PinnedTokenProvider {
    token_provider: TokenProvider,
    token_name: TokenName,
}

impl ProvidesPinnedToken for PinnedTokenProvider {
    fn get_token(&self) -> Result<AccessToken> {
        self.token_provider.get_token(&self.token_name)
    }

    fn refresh(&self) {
        self.token_provider.refresh(&self.token_name)
    }
}

pub struct TokenManager;

impl TokenManager {
    pub fn start(groups: Vec<ManagedTokenGroup>) -> TokenProvider {
        let (inner, sender) = internals::initialize(groups);
        TokenProvider { inner, sender }
    }
}
