//! Managing `AccessToken`s.
//!
//! `AccessToken`s are managed by configuring a `ManagedToken`.
//! They can later be queried by the identifier configured with
//! the `ManagedToken`. The identifier can be any type `T` where
//! `T: Eq + Ord + Send + Sync + Clone + Display + 'static`
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread;
use std::result::Result as StdResult;
use std::fmt::Display;
use std::collections::BTreeMap;
use std::env;
use {AccessToken, Scope};


mod error;
pub mod tokenprovider;
mod internals;

pub use self::error::*;
use self::tokenprovider::*;
use self::internals::Inner;
use super::{InitializationError, InitializationResult};

/// A builder to configure a `ManagedToken`.
pub struct ManagedTokenBuilder<T> {
    pub token_id: Option<T>,
    pub scopes: Vec<Scope>,
}

impl<T: Eq + Send + Clone + Display> ManagedTokenBuilder<T> {
    /// Sets the token identifier to identify and query the managed token.
    ///
    /// Setting the identifier is mandatory.
    pub fn with_identifier(&mut self, token_id: T) -> &mut Self {
        self.token_id = Some(token_id);
        self
    }

    /// Adds a `Scope` to be granted by the `AccessToken`.
    pub fn with_scope(&mut self, scope: Scope) -> &mut Self {
        self.scopes.push(scope);
        self
    }

    /// Adds multiple `Scope`s to be granted by the `AccessToken`.
    pub fn with_scopes(&mut self, scopes: Vec<Scope>) -> &mut Self {
        for scope in scopes {
            self.scopes.push(scope);
        }
        self
    }

    pub fn with_scopes_from_env(&mut self) -> StdResult<&mut Self, InitializationError> {
        self.with_scopes_from_selected_env_var("TOKKIT_MANAGED_TOKEN_SCOPES")
    }

    pub fn with_scopes_from_selected_env_var(
        &mut self,
        env_name: &str,
    ) -> StdResult<&mut Self, InitializationError> {
        match env::var(env_name) {
            Ok(v) => {
                let scopes = split_scopes(&v);
                self.with_scopes(scopes)
            }
            Err(err) => bail!(err),
        };
        Ok(self)
    }

    /// Builds the managed token if properly configured.
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

fn split_scopes(input: &str) -> Vec<Scope> {
    input
        .split(' ')
        .filter(|s| s.len() > 0)
        .map(Scope::new)
        .collect()
}

impl ManagedTokenBuilder<String> {
    pub fn with_id_from_env(&mut self) -> StdResult<&mut Self, InitializationError> {
        self.with_id_from_selected_env_var("TOKKIT_MANAGED_TOKEN_ID")
    }

    pub fn with_id_from_selected_env_var(
        &mut self,
        env_name: &str,
    ) -> StdResult<&mut Self, InitializationError> {
        match env::var(env_name) {
            Ok(v) => self.token_id = Some(v),
            Err(err) => bail!(err),
        };
        Ok(self)
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

/// An `AccessToken` to be managed.
/// The `AccessToken` will be updated automatically.
pub struct ManagedToken<T> {
    pub token_id: T,
    pub scopes: Vec<Scope>,
}

pub struct ManagedTokenGroupBuilder<
    T: Eq + Send + Clone + Display,
    S: AccessTokenProvider + 'static,
> {
    token_provider: Option<Arc<S>>,
    managed_tokens: Vec<ManagedToken<T>>,
    refresh_threshold: f32,
    warning_threshold: f32,
}

impl<T: Eq + Send + Clone + Display, S: AccessTokenProvider + Send + Sync + 'static>
    ManagedTokenGroupBuilder<T, S> {
    pub fn with_token_provider(&mut self, token_provider: S) -> &mut Self {
        self.token_provider = Some(Arc::new(token_provider));
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

    pub fn single_token(token_id: T, scopes: Vec<Scope>, token_provider: S) -> Self {
        let managed_token = ManagedToken { token_id, scopes };
        let mut builder = Self::default();
        builder.with_managed_token(managed_token);
        builder.with_token_provider(token_provider);

        builder
    }

    pub fn build(self) -> StdResult<ManagedTokenGroup<T>, InitializationError> {
        let token_provider = if let Some(token_provider) = self.token_provider {
            token_provider
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
            token_provider: token_provider,
            managed_tokens: self.managed_tokens,
            refresh_threshold: self.refresh_threshold,
            warning_threshold: self.warning_threshold,
        })
    }
}

impl<T: Eq + Send + Clone + Display, S: AccessTokenProvider + 'static> Default
    for ManagedTokenGroupBuilder<T, S> {
    fn default() -> Self {
        ManagedTokenGroupBuilder {
            token_provider: Default::default(),
            managed_tokens: Default::default(),
            refresh_threshold: 0.75,
            warning_threshold: 0.85,
        }
    }
}

/// A group of `ManagedToken`s that are requested from the same authorization server
pub struct ManagedTokenGroup<T> {
    /// The
    pub token_provider: Arc<AccessTokenProvider + Send + Sync + 'static>,
    pub managed_tokens: Vec<ManagedToken<T>>,
    pub refresh_threshold: f32,
    pub warning_threshold: f32,
}

/// Can be queired for `AccessToken`s by their
/// identifier configured with the respective
/// `ManagedToken`.
#[derive(Clone)]
pub struct AccessTokenSource<T> {
    inner: Arc<Inner<T>>,
    sender: Sender<internals::ManagerCommand<T>>,
}

impl<T: Eq + Ord + Clone + Display> AccessTokenSource<T> {
    /// Get an `AccessToken` by identifier.
    pub fn get_access_token(&self, token_id: &T) -> Result<AccessToken> {
        match self.inner.tokens.get(&token_id) {
            Some(&(_, ref guard)) => match &*guard.lock().unwrap() {
                &Ok(ref token) => Ok(token.clone()),
                &Err(ref err) => bail!(err.clone()),
            },
            None => bail!(ErrorKind::NoToken(token_id.to_string())),
        }
    }

    /// Refresh the `AccessToken` for the given identifier.
    pub fn refresh(&self, name: &T) {
        self.sender
            .send(internals::ManagerCommand::ForceRefresh(
                name.clone(),
                internals::Clock::now(&internals::SystemClock),
            ))
            .unwrap()
    }

    /// Get a `SingleAccessTokenSource` for the given identifier.
    ///
    /// Fails if no `ManagedToken` with the given id exists.
    pub fn single_source_for(&self, token_id: &T) -> Result<SingleAccessTokenSource<T>> {
        match self.inner.tokens.get(token_id) {
            Some(_) => Ok(SingleAccessTokenSource {
                token_source: self.clone(),
                token_id: token_id.clone(),
            }),
            None => Err(ErrorKind::NoToken(token_id.to_string()).into()),
        }
    }
}

/// Can be queried for a fixed `AccessToken`.
#[derive(Clone)]
pub struct SingleAccessTokenSource<T> {
    token_source: AccessTokenSource<T>,
    token_id: T,
}

impl<T: Eq + Ord + Clone + Display> SingleAccessTokenSource<T> {
    /// Get the `AccessToken`.
    pub fn get_access_token(&self) -> Result<AccessToken> {
        self.token_source.get_access_token(&self.token_id)
    }

    pub fn refresh(&self) {
        self.token_source.refresh(&self.token_id)
    }
}

/// The `TokenManager` refreshes `AccessTokens`s in the background.
///
/// It will run as long as any `AccessTokenSource` or
/// `SingleAccessTokenSource` is in scope.
pub struct AccessTokenManager;

impl AccessTokenManager {
    /// Starts the `AccessTokenManager` in the background.
    pub fn start<T: Eq + Ord + Send + Sync + Clone + Display + 'static>(
        groups: Vec<ManagedTokenGroup<T>>,
    ) -> InitializationResult<AccessTokenSource<T>> {
        {
            let mut seen = BTreeMap::default();
            for group in &groups {
                for managed_token in &group.managed_tokens {
                    let token_id = &managed_token.token_id;
                    if seen.contains_key(token_id) {
                        bail!(InitializationError(
                            format!("Token id '{}' is used more than once.", token_id),
                        ))
                    } else {
                        seen.insert(token_id, ());
                    }
                }
            }
        }
        let (inner, sender) = internals::initialize(groups, internals::SystemClock);
        Ok(AccessTokenSource { inner, sender })
    }
}
