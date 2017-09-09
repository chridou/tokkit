//! Token verification for protected resources on resource servers.
//!
//! See [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
//! and
//! [Roles](https://tools.ietf.org/html/rfc6749#section-1.1)
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
    fn introspect(&self, token: &AccessToken) -> Result<TokenInfo>;
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
    /// REQUIRED.  Boolean indicator of whether or not the presented token
    /// is currently active.  The specifics of a token's "active" state
    /// will vary depending on the implementation of the authorization
    /// server and the information it keeps about its tokens, but a "true"
    /// value return for the "active" property will generally indicate
    /// that a given token has been issued by this authorization server,
    /// has not been revoked by the resource owner, and is within its
    /// given time window of validity (e.g., after its issuance time and
    /// before its expiration time).
    /// See [Section 4](https://tools.ietf.org/html/rfc7662#section-4)
    /// for information on implementation of such checks.
    pub active: bool,
    /// OPTIONAL.  Human-readable identifier for the resource owner who
    /// authorized this token.
    ///
    /// Remark: This is usually not a human readable id but a custom field
    /// since we are in the realm of S2S authorization.
    pub user_id: Option<UserId>,
    /// OPTIONAL.  A JSON string containing a space-separated list of
    /// scopes associated with this token, in the format described in
    /// [Section 3.3](https://tools.ietf.org/html/rfc7662#section-5.1)
    /// of OAuth 2.0 [RFC6749](https://tools.ietf.org/html/rfc6749).
    pub scope: Vec<Scope>,
    /// OPTIONAL.  Integer timestamp, measured in the number of seconds
    /// since January 1 1970 UTC, indicating when this token will expire,
    /// as defined in JWT [RFC7519](https://tools.ietf.org/html/rfc7519).
    ///
    /// Remark: Contains the number of seconds until the token expires.
    /// This seems to be used by most introspection services.
    pub expires_in_seconds: Option<u64>,
}

impl TokenInfo {
    /// Use for authorization. Checks whether this `TokenInfo` has the given `Scope`.
    pub fn has_scope(&self, scope: &Scope) -> bool {
        self.scope.iter().find(|&s| s == scope).is_some()
    }

    /// Use for authorization. Checks whether this `TokenInfo` has all of the given `Scopes`.
    pub fn has_scopes(&self, scopes: &[Scope]) -> bool {
        scopes.iter().all(|scope| self.has_scope(scope))
    }

    /// If the `TokenInfo` does not have the scope this method will fail.
    pub fn must_have_scope(&self, scope: &Scope) -> ::std::result::Result<(), NotAuthorized> {
        if self.has_scope(scope) {
            Ok(())
        } else {
            Err(NotAuthorized(
                format!("Required scope '{}' not present.", scope),
            ))
        }
    }
}

/// There is no authorization for the requested resource
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
