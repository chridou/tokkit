//! Token verification for protected resources on resource servers.
//!
//! See [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
//! and
//! [Roles](https://tools.ietf.org/html/rfc6749#page-5)
use std::fmt;
use super::*;

pub mod error;
pub mod parsers;
mod remote;

pub use self::remote::*;
use self::error::*;

/// A parser that can parse a slice of bytes to a `TokenInfo`
pub trait TokenInfoParser: 'static {
    fn parse(&self, bytes: &[u8]) -> ::std::result::Result<TokenInfo, String>;
}

impl TokenInfoParser for Fn(&[u8]) -> ::std::result::Result<TokenInfo, String> {
    /// Parse a slice of bytes to a `TokenInfo`
    fn parse(&self, bytes: &[u8]) -> ::std::result::Result<TokenInfo, String> {
        self(bytes)
    }
}

/// Gives a `TokenInfo` for an `AccessToken`.
///
/// See [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
pub trait TokenInfoService {
    /// Gives a `TokenInfo` fa an `AccessToken`.
    fn get_token_info(&self, token: &AccessToken) -> Result<TokenInfo>;

    /// Returns an `User` if a `UserId` is present.
    fn get_user(&self, token: &AccessToken) -> Result<User> {
        let authenticated = self.get_token_info(token)?;
        if let Some(user_id) = authenticated.user_id {
            Ok({
                User {
                    user_id: user_id,
                    scopes: authenticated.scopes,
                }
            })
        } else {
            bail!(ErrorKind::NotAUser(
                "User id is missing in token info".to_string(),
            ))
        }
    }
}

/// An id that uniquely identifies the owner of a protected resource
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct UserId(pub String);

impl UserId {
    pub fn new<T: Into<String>>(uid: T) -> UserId {
        UserId(uid.into())
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Information on an `AccessToken` returned by a `TokenInfoService`.
///
/// See [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
#[derive(Debug, PartialEq)]
pub struct TokenInfo {
    pub user_id: Option<UserId>,
    pub scopes: Vec<Scope>,
    pub expires_in_seconds: u64,
}

/// A known user.
#[derive(Debug)]
pub struct User {
    pub user_id: UserId,
    pub scopes: Vec<Scope>,
}

impl User {
    /// Create a new `User` with just a `UserId`
    pub fn new(user_id: UserId) -> Self {
        User {
            user_id: user_id,
            scopes: Vec::new(),
        }
    }

    /// Use for authorization. Checks whether this user has the given `Scope`.
    pub fn has_scope(&self, scope: &Scope) -> bool {
        self.scopes.iter().find(|&s| s == scope).is_some()
    }

    /// Use for authorization. Checks whether this user has all of the given `Scopes`.
    pub fn has_scopes(&self, scopes: &[Scope]) -> bool {
        scopes.iter().all(|scope| self.has_scope(scope))
    }

    /// Authorize the user for an action defined by the given scope.
    /// If the user does not have the scope this method will fail.
    pub fn must_have_scope(&self, scope: &Scope) -> ::std::result::Result<(), NotAuthorized> {
        if self.has_scope(scope) {
            Ok(())
        } else {
            Err(NotAuthorized(format!(
                "User '{}' does not have the required scope '{}'.",
                self.user_id,
                scope
            )))
        }
    }
}

/// There is no athorization for the requested resource
#[derive(Debug)]
pub struct NotAuthorized(String);

impl NotAuthorized {
    pub fn new<T: Into<String>>(msg: T) -> NotAuthorized {
        NotAuthorized(msg.into())
    }
}

impl fmt::Display for NotAuthorized {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Not authorized: {}", self.0)
    }
}

impl ::std::error::Error for NotAuthorized {
    fn description(&self) -> &str {
        "not authorized"
    }

    fn cause(&self) -> Option<&::std::error::Error> {
        None
    }
}
