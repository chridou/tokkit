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
use super::InitializationError;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TokenName(pub String);

impl fmt::Display for TokenName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub struct ManagedTokenBuilder {
    pub name: Option<TokenName>,
    pub scopes: Vec<Scope>,
}

impl ManagedTokenBuilder {
    pub fn with_name(&mut self, name: TokenName) -> &mut Self {
        self.name = Some(name);
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

    pub fn build(self) -> StdResult<ManagedToken, InitializationError> {
        let name = if let Some(name) = self.name {
            name
        } else {
            bail!(InitializationError("Token name is mandatory".to_string()))
        };

        Ok(ManagedToken {
            name: name,
            scopes: self.scopes,
        })
    }
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

pub struct ManagedTokenGroupBuilder<S: TokenService + 'static> {
    token_service: Option<Arc<S>>,
    managed_tokens: Vec<ManagedToken>,
    refresh_threshold: f32,
    warning_threshold: f32,
}

impl<S: TokenService + Send + Sync + 'static> ManagedTokenGroupBuilder<S> {
    pub fn with_token_service(&mut self, token_service: S) -> &mut Self {
        self.token_service = Some(Arc::new(token_service));
        self
    }

    pub fn with_managed_token(&mut self, managed_token: ManagedToken) -> &mut Self {
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

    pub fn with_managed_token_from_builder(&mut self, builder: ManagedTokenBuilder)
    -> StdResult<&mut Self, InitializationError> {
        let managed_token = builder.build()?;
        Ok(self.with_managed_token(managed_token))
    }

    pub fn build(self) -> StdResult<ManagedTokenGroup, InitializationError> {
        let token_service = if let Some(token_service) = self.token_service {
            token_service
        } else {
            bail!(InitializationError("Token service is mandatory".to_string()))
        };
        
        if self.managed_tokens.is_empty() {
             bail!(InitializationError("Managed Tokens must not be empty".to_string()))           
        }

        if self.refresh_threshold <= 0.0 || self.refresh_threshold > 1.0 {
             bail!(InitializationError("Refresh threshold must be of (0;1]".to_string()))           
        }

        if self.warning_threshold <= 0.0 || self.warning_threshold > 1.0 {
             bail!(InitializationError("Warning threshold must be of (0;1]".to_string()))           
        }


        Ok(ManagedTokenGroup {
    token_service: token_service,
    managed_tokens: self.managed_tokens,
    refresh_threshold: self.refresh_threshold,
    warning_threshold: self.warning_threshold,
})
    }
}

impl<S: TokenService + 'static> Default for ManagedTokenGroupBuilder<S> {
    fn default() -> Self {
        ManagedTokenGroupBuilder {
            token_service: Default::default(),
            managed_tokens: Default::default(),
            refresh_threshold: 0.75,
            warning_threshold: 0.85,
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
        let (inner, sender) = internals::initialize(groups, internals::SystemClock);
        TokenProvider { inner, sender }
    }
}
