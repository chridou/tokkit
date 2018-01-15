//! Managing `AccessToken`s.
//!
//! `AccessToken`s are managed by configuring a `ManagedToken`.
//! They can later be queried by the identifier configured with
//! the `ManagedToken`. The identifier can be any type `T` where
//! `T: Eq + Ord + Send + Sync + Clone + Display + 'static`
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread;
use std::result::Result as StdResult;
use std::fmt::Display;
use std::collections::BTreeMap;
use std::env;
use std::time::{Duration, Instant};
use {AccessToken, Scope};

mod error;
pub mod token_provider;
mod internals;

pub use self::error::*;
use self::token_provider::*;
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

    /// Adds `Scope`s from the environment. They are read from
    /// `TOKKIT_MANAGED_TOKEN_SCOPES` and must be separated by spaces.
    pub fn with_scopes_from_env(&mut self) -> StdResult<&mut Self, InitializationError> {
        self.with_scopes_from_selected_env_var("TOKKIT_MANAGED_TOKEN_SCOPES")
    }

    /// Adds `Scope`s from the environment. They are read from
    /// an environment variable with the given name and must be separated by spaces.
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
    /// Sets the `token_id` for this managed token from an environment variable.
    /// The `token_id` is read from `TOKKIT_MANAGED_TOKEN_ID`.
    pub fn with_id_from_env(&mut self) -> StdResult<&mut Self, InitializationError> {
        self.with_id_from_selected_env_var("TOKKIT_MANAGED_TOKEN_ID")
    }

    /// Sets the `token_id` for this managed token from an environment variable.
    /// The `token_id` is read from an environment variable with the given name.
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

pub struct ManagedTokenGroupBuilder<T, S: AccessTokenProvider + 'static> {
    token_provider: Option<Arc<S>>,
    managed_tokens: Vec<ManagedToken<T>>,
    refresh_threshold: f32,
    warning_threshold: f32,
}

impl<T: Eq + Send + Clone + Display, S: AccessTokenProvider + Send + Sync + 'static>
    ManagedTokenGroupBuilder<T, S> {
    /// Sets the `AccessTokenProvider` for this group of `ManagedToken`s.
    /// This is a mandatory value.
    pub fn with_token_provider(&mut self, token_provider: S) -> &mut Self {
        self.token_provider = Some(Arc::new(token_provider));
        self
    }

    /// Adds a `ManagedToken` to this group.
    pub fn with_managed_token(&mut self, managed_token: ManagedToken<T>) -> &mut Self {
        self.managed_tokens.push(managed_token);
        self
    }

    /// Sets the refresh interval as a percentage of the "expires in" sent
    /// by the authorization server. The default is `0.75`
    pub fn with_refresh_threshold(&mut self, refresh_threshold: f32) -> &mut Self {
        self.refresh_threshold = refresh_threshold;
        self
    }

    /// Sets the warnoing interval as a percentage of the "expires in" sent
    /// by the authorization server. The default is `0.85`
    pub fn with_warning_threshold(&mut self, warning_threshold: f32) -> &mut Self {
        self.refresh_threshold = warning_threshold;
        self
    }

    /// Adds a `ManagedToken` built from the given `ManagedTokenBuilder`.
    pub fn with_managed_token_from_builder(
        &mut self,
        builder: ManagedTokenBuilder<T>,
    ) -> StdResult<&mut Self, InitializationError> {
        let managed_token = builder.build()?;
        Ok(self.with_managed_token(managed_token))
    }

    /// Sets everything needed to manage the give token.
    pub fn single_token(token_id: T, scopes: Vec<Scope>, token_provider: S) -> Self {
        let managed_token = ManagedToken { token_id, scopes };
        let mut builder = Self::default();
        builder.with_managed_token(managed_token);
        builder.with_token_provider(token_provider);

        builder
    }

    /// Build the `ManagedTokenGroup`.
    ///
    /// Fails if not all required fields are set properly.
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

/// A group of `ManagedToken`s that are requested from the same authorization
/// server
pub struct ManagedTokenGroup<T> {
    /// The
    pub token_provider: Arc<AccessTokenProvider + Send + Sync + 'static>,
    pub managed_tokens: Vec<ManagedToken<T>>,
    pub refresh_threshold: f32,
    pub warning_threshold: f32,
}

/// Keeps track of running client for global shutdown
struct IsRunningGuard {
    is_running: Arc<AtomicBool>,
}

impl Default for IsRunningGuard {
    fn default() -> IsRunningGuard {
        IsRunningGuard {
            is_running: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl Drop for IsRunningGuard {
    fn drop(&mut self) {
        self.is_running.store(false, Ordering::Relaxed);
    }
}

/// Can be queired for `AccessToken`s by their
/// identifier configured with the respective
/// `ManagedToken`.
pub trait GivesAccessTokensById<T: Eq + Ord + Clone + Display> {
    /// Get an `AccessToken` by identifier.
    fn get_access_token(&self, token_id: &T) -> Result<AccessToken>;
    /// Refresh the `AccessToken` for the given identifier.
    fn refresh(&self, name: &T);
}

#[derive(Clone)]
pub struct AccessTokenSource<T> {
    tokens: Arc<BTreeMap<T, (usize, Mutex<StdResult<AccessToken, ErrorKind>>)>>,
    sender: Sender<internals::ManagerCommand<T>>,
    is_running: Arc<IsRunningGuard>,
}

impl<T: Eq + Ord + Clone + Display> AccessTokenSource<T> {
    /// Get a `SingleAccessTokenSource` for the given identifier.
    ///
    /// Fails if no `ManagedToken` with the given id exists.
    pub fn single_source_for(&self, token_id: &T) -> Result<FixedAccessTokenSource<T>> {
        match self.tokens.get(token_id) {
            Some(_) => Ok(FixedAccessTokenSource {
                token_source: self.clone(),
                token_id: token_id.clone(),
            }),
            None => Err(ErrorKind::NoToken(token_id.to_string()).into()),
        }
    }

    /// Creates a new `AccessTokenSource` which is not attached to an `AccessTokenManager`.
    ///
    /// This means the `AccessTokenSource` is not updated in the background and
    /// should only be used in a testing context or where you know that the
    /// `AccessToken`s do not need to be updated in the background(CLI etc).
    ///
    /// The `refresh` method will not do anything meaningful...
    pub fn new_detached(tokens: &[(T, AccessToken)]) -> AccessTokenSource<T> {
        let mut tokens_map = BTreeMap::new();

        for (i, &(ref id, ref token)) in tokens.into_iter().enumerate() {
            let item = (i, Mutex::new(Ok(token.clone())));
            tokens_map.insert(id.clone(), item);
        }

        let (tx, _) = ::std::sync::mpsc::channel::<internals::ManagerCommand<T>>();

        AccessTokenSource {
            tokens: Arc::new(tokens_map),
            is_running: Default::default(),
            sender: tx,
        }
    }
}

impl<T: Eq + Ord + Clone + Display> GivesAccessTokensById<T> for AccessTokenSource<T> {
    fn get_access_token(&self, token_id: &T) -> Result<AccessToken> {
        match self.tokens.get(&token_id) {
            Some(&(_, ref guard)) => match &*guard.lock().unwrap() {
                &Ok(ref token) => Ok(token.clone()),
                &Err(ref err) => bail!(err.clone()),
            },
            None => bail!(ErrorKind::NoToken(token_id.to_string())),
        }
    }

    fn refresh(&self, name: &T) {
        match self.sender.send(internals::ManagerCommand::ForceRefresh(
            name.clone(),
            internals::Clock::now(&internals::SystemClock),
        )) {
            Ok(_) => (),
            Err(err) => warn!("Could send send refresh command for {}: {}", name, err),
        }
    }
}

/// Can be queried for a fixed `AccessToken`.
///
/// This means the `token_id` for the `AccessToken` to be delivered
/// has been previously selected.
pub trait GivesFixedAccessToken<T: Eq + Ord + Clone + Display> {
    /// Get the `AccessToken`.
    fn get_access_token(&self) -> Result<AccessToken>;

    /// Refresh the `AccessToken`
    fn refresh(&self);
}

#[derive(Clone)]
pub struct FixedAccessTokenSource<T> {
    token_source: AccessTokenSource<T>,
    token_id: T,
}

impl<T: Eq + Ord + Clone + Display> GivesFixedAccessToken<T> for FixedAccessTokenSource<T> {
    fn get_access_token(&self) -> Result<AccessToken> {
        self.token_source.get_access_token(&self.token_id)
    }

    fn refresh(&self) {
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
                        bail!(InitializationError(format!(
                            "Token id '{}' is used more than once.",
                            token_id
                        ),))
                    } else {
                        seen.insert(token_id, ());
                    }
                }
            }
        }
        let (inner, sender) = internals::initialize(groups, internals::SystemClock);
        Ok(AccessTokenSource {
            tokens: inner.tokens,
            sender,
            is_running: Arc::new(IsRunningGuard {
                is_running: inner.is_running,
            }),
        })
    }

    /// Starts the `AccessTokenManager` in the background and waits until all
    /// tokens have been initialized or a timeout elapsed..
    pub fn start_and_wait<T: Eq + Ord + Send + Sync + Clone + Display + 'static>(
        groups: Vec<ManagedTokenGroup<T>>,
        timeout_in: Duration,
    ) -> InitializationResult<AccessTokenSource<T>> {
        {
            let mut seen = BTreeMap::default();
            for group in &groups {
                for managed_token in &group.managed_tokens {
                    let token_id = &managed_token.token_id;
                    if seen.contains_key(token_id) {
                        bail!(InitializationError(format!(
                            "Token id '{}' is used more than once.",
                            token_id
                        ),))
                    } else {
                        seen.insert(token_id, ());
                    }
                }
            }
        }

        let (inner, sender) = internals::initialize(groups, internals::SystemClock);

        let start = Instant::now();
        loop {
            if start.elapsed() >= timeout_in {
                return Err(InitializationError(
                    "Not all tokens were initialized within the \
                     given time."
                        .into(),
                ));
            }

            let all_initialized = inner.tokens.keys().all(|id| {
                if let Err(Error(ErrorKind::NotInitialized(_), _)) = inner.get_access_token(id) {
                    true
                } else {
                    false
                }
            });

            if all_initialized {
                break;
            }

            ::std::thread::sleep(Duration::from_millis(10));
        }

        Ok(AccessTokenSource {
            tokens: inner.tokens,
            sender,
            is_running: Arc::new(IsRunningGuard {
                is_running: inner.is_running,
            }),
        })
    }
}
