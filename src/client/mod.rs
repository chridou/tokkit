use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
}

#[derive(Clone)]
pub struct TokenProvider {
    inner: Arc<Inner>,
}

impl ProvidesTokens for TokenProvider {
    fn get_token(&self, name: &TokenName) -> Result<AccessToken> {
        self.inner.get_token(name)
    }
}


pub struct TokenManager {
    inner: Arc<internals::Inner>,
}

impl TokenManager {
    pub fn start(groups: Vec<ManagedTokenGroup>) -> TokenManager {
        let inner = internals::initialize(groups);
        TokenManager { inner }
    }

    pub fn stop(&self) {
        self.inner.is_running.store(false, Ordering::Relaxed);
    }

    pub fn is_running(&self) -> bool {
        self.inner.is_running.load(Ordering::Relaxed)
    }
}

impl ProvidesTokens for TokenManager {
    fn get_token(&self, name: &TokenName) -> Result<AccessToken> {
        self.inner.get_token(name)
    }
}
