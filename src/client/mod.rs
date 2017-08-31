use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Instant;
use std::result::Result as StdResult;
use std::fmt::Display;
use {AccessToken, Scope};

pub mod error;
pub mod tokenservice;
mod internals;

use self::error::*;
use self::tokenservice::*;
use self::internals::Inner;
use super::InitializationError;

pub struct ManagedTokenBuilder<T> {
    pub token_id: Option<T>,
    pub scopes: Vec<Scope>,
}

impl<T: Eq + Send + Clone + Display> ManagedTokenBuilder<T> {
    pub fn with_name(&mut self, token_id: T) -> &mut Self {
        self.token_id = Some(token_id);
        self
    }

    pub fn with_scope(&mut self, scope: Scope) -> &mut Self {
        self.scopes.push(scope);
        self
    }

    pub fn with_scopes(&mut self, scopes: Vec<Scope>) -> &mut Self {
        for scope in scopes {
            self.scopes.push(scope);
        }
        self
    }

    pub fn build(self) -> StdResult<ManagedToken<T>, InitializationError> {
        let token_id = if let Some(token_id) = self.token_id {
            token_id
        } else {
            bail!(InitializationError("Token name is mandatory".to_string()))
        };

        Ok(ManagedToken {
            token_id: token_id,
            scopes: self.scopes,
        })
    }
}

impl<T: Eq + Send + Clone + Display> Default for ManagedTokenBuilder<T> {
    fn default() -> Self {
        ManagedTokenBuilder {
            token_id: Default::default(),
            scopes: Default::default(),
        }
    }
}

pub struct ManagedToken<T> {
    token_id: T,
    scopes: Vec<Scope>,
}

pub struct ManagedTokenGroupBuilder<T: Eq + Send + Clone + Display,S: TokenService + 'static 
> {
    token_service: Option<Arc<S>>,
    managed_tokens: Vec<ManagedToken<T>>,
    refresh_threshold: f32,
    warning_threshold: f32,
}

impl<T: Eq + Send + Clone + Display, S: TokenService + Send + Sync + 'static,
> ManagedTokenGroupBuilder<T, S> {
    pub fn with_token_service(&mut self, token_service: S) -> &mut Self {
        self.token_service = Some(Arc::new(token_service));
        self
    }

    pub fn with_managed_token(&mut self, managed_token: ManagedToken<T>) -> &mut Self {
        self.managed_tokens.push(managed_token);
        self
    }

    pub fn with_refresh_threshold(&mut self, refresh_threshold: f32) -> &mut Self {
        self.refresh_threshold = refresh_threshold;
        self
    }

    pub fn with_warning_threshold(&mut self, warning_threshold: f32) -> &mut Self {
        self.refresh_threshold = warning_threshold;
        self
    }

    pub fn with_managed_token_from_builder(
        &mut self,
        builder: ManagedTokenBuilder<T>,
    ) -> StdResult<&mut Self, InitializationError> {
        let managed_token = builder.build()?;
        Ok(self.with_managed_token(managed_token))
    }

    pub fn build(self) -> StdResult<ManagedTokenGroup<T>, InitializationError> {
        let token_service = if let Some(token_service) = self.token_service {
            token_service
        } else {
            bail!(InitializationError(
                "Token service is mandatory".to_string(),
            ))
        };

        if self.managed_tokens.is_empty() {
            bail!(InitializationError(
                "Managed Tokens must not be empty".to_string(),
            ))
        }

        if self.refresh_threshold <= 0.0 || self.refresh_threshold > 1.0 {
            bail!(InitializationError(
                "Refresh threshold must be of (0;1]".to_string(),
            ))
        }

        if self.warning_threshold <= 0.0 || self.warning_threshold > 1.0 {
            bail!(InitializationError(
                "Warning threshold must be of (0;1]".to_string(),
            ))
        }


        Ok(ManagedTokenGroup {
            token_service: token_service,
            managed_tokens: self.managed_tokens,
            refresh_threshold: self.refresh_threshold,
            warning_threshold: self.warning_threshold,
        })
    }
}

impl<T: Eq + Send + Clone + Display,
S: TokenService + 'static> Default for ManagedTokenGroupBuilder<T, S> {
    fn default() -> Self {
        ManagedTokenGroupBuilder {
            token_service: Default::default(),
            managed_tokens: Default::default(),
            refresh_threshold: 0.75,
            warning_threshold: 0.85,
        }
    }
}

pub struct ManagedTokenGroup<T> {
    token_service: Arc<TokenService + Send + Sync + 'static>,
    managed_tokens: Vec<ManagedToken<T>>,
    refresh_threshold: f32,
    warning_threshold: f32,
}

pub trait ProvidesTokens<T> {
    fn get_token(&self, token_id: &T) -> Result<AccessToken>;
    fn refresh(&self, token_id: &T);
    fn pinned_provider(&self, token_id: &T) -> Result<PinnedTokenProvider<T>>;
}

pub trait ProvidesPinnedToken {
    fn get_token(&self) -> Result<AccessToken>;
    fn refresh(&self);
}

#[derive(Clone)]
pub struct TokenProvider<T> {
    inner: Arc<Inner<T>>,
    sender: Sender<internals::ManagerCommand<T>>,
}

impl<T: Eq  + Ord + Clone + Display> ProvidesTokens<T> for TokenProvider<T> {
    fn get_token(&self, token_id: &T) -> Result<AccessToken> {
        match self.inner.tokens.get(&token_id) {
            Some(&(_, ref guard)) => {
                match &*guard.lock().unwrap() {
                    &Ok(ref token) => Ok(token.clone()),
                    &Err(ref err) => bail!(err.clone()),
                }
            }
            None => bail!(ErrorKind::NoToken(token_id.to_string())),
        }
    }

    fn refresh(&self, name: &T) {
        self.sender
            .send(internals::ManagerCommand::ForceRefresh(
                name.clone(),
                Instant::now(),
            ))
            .unwrap()
    }

    fn pinned_provider(&self, token_id: &T) -> Result<PinnedTokenProvider<T>> {
        match self.inner.tokens.get(token_id) {
            Some(_) => Ok(PinnedTokenProvider {
                token_provider: self.clone(),
                token_id: token_id.clone(),
            }),
            None => Err(ErrorKind::NoToken(token_id.to_string()).into()),
        }
    }
}

#[derive(Clone)]
pub struct PinnedTokenProvider<T> {
    token_provider: TokenProvider<T>,
    token_id: T,
}

impl<T: Eq  + Ord + Clone + Display> ProvidesPinnedToken for PinnedTokenProvider<T> {
    fn get_token(&self) -> Result<AccessToken> {
        self.token_provider.get_token(&self.token_id)
    }

    fn refresh(&self) {
        self.token_provider.refresh(&self.token_id)
    }
}

pub struct TokenManager;

impl TokenManager {
    pub fn start<T: Eq + Ord + Send + Sync + Clone + Display + 'static>(groups: Vec<ManagedTokenGroup<T>>) -> TokenProvider<T> {
        let (inner, sender) = internals::initialize(groups, internals::SystemClock);
        TokenProvider { inner, sender }
    }
}
