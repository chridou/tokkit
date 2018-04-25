//! # tokkit
//!
//! [![crates.io](https://img.shields.io/crates/v/tokkit.svg)](https://crates.io/crates/tokkit)
//! [![docs.rs](https://docs.rs/tokkit/badge.svg)](https://docs.rs/tokkit)
//! [![downloads](https://img.shields.io/crates/d/tokkit.svg)](https://crates.io/crates/tokkit)
//! [![build Status](https://travis-ci.org/chridou/tokkit.svg?branch=master)](https://travis-ci.
//! org/chridou/tokkit)
//! [![license-mit](http://img.shields.io/badge/license-MIT-blue.svg)](https://github.
//! com/chridou/tokkit/blob/master/LICENSE-MIT)
//! [![license-apache](http://img.shields.io/badge/license-APACHE-blue.svg)](https://github.
//! com/chridou/tokkit/blob/master/LICENSE-APACHE)
//!
//! `tokkit` is a simple(even simplistic) **tok**en tool**kit** for OAUTH2 token
//! introspection
//!
//! ## Adding tokkit to your project
//!
//! tokkit is available on [crates.io](https://crates.io/crates/tokkit).
//!
//! ## Documentation
//!
//! The documentation is available [online](https://docs.rs/tokkit).
//!
//! ## Features
//!
//! * `async`: Adds a `hyper` based async client.
//! See also `TokenInfoServiceClientBuilder`
//! * `metrix`: Add support for the [metrix](https://crates.io/crates/metrix)
//! crate(async client only)
//! See also `TokenInfoServiceClientBuilder`
//!
//! ### Verify Access Tokens
//!
//! `tokkit` contains a module `token_info` for protected resources to verify access tokens.
//!
//! ```rust,no_run
//! use tokkit::*;
//! use tokkit::client::*;
//!
//! let builder = TokenInfoServiceClientBuilder::google_v3();
//!
//! let service = builder.build().unwrap();
//!
//! let token = AccessToken::new("<token>");
//!
//! let tokeninfo = service.introspect(&token).unwrap();
//! ```
//!
//! ## Recent changes
//!
//! * 0.8.4
//!    * Added support for [metrix](https://crates.io/crates/metrix)
//! * 0.8.3
//!    * Added metrics
//! * 0.8.2
//!    * Added retries for async client
//! * 0.8.1
//!    * Added experimental support for async client.
//!
//! ## License
//!
//! tokkit is primarily distributed under the terms of
//! both the MIT license and the Apache License (Version 2.0).
//!
//! Copyright (c) 2017 Christian Douven
//! Token verification for protected resources on resource servers.
//!
//! See [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
//! and
//! [Roles](https://tools.ietf.org/html/rfc6749#section-1.1)
#[macro_use]
extern crate log;

extern crate backoff;
#[macro_use]
extern crate failure;
extern crate json;
extern crate reqwest;
extern crate url;

#[cfg(feature = "async")]
extern crate futures;
#[cfg(feature = "async")]
extern crate hyper;
#[cfg(feature = "async")]
extern crate hyper_tls;
#[cfg(feature = "metrix")]
extern crate metrix;
#[cfg(feature = "async")]
extern crate tokio_core;
#[cfg(feature = "async")]
extern crate tokio_retry;

use std::fmt;

mod error;
pub mod token_manager;
pub mod parsers;
pub mod client;
#[cfg(feature = "async")]
pub mod async_client;
pub mod metrics;

pub use error::{TokenInfoError, TokenInfoErrorKind, TokenInfoResult};

/// An access token
///
/// See [RFC6749](https://tools.ietf.org/html/rfc6749#section-1.4)
#[derive(Clone)]
pub struct AccessToken(pub String);

impl AccessToken {
    /// Creates a new `AccessToken`
    pub fn new<T: Into<String>>(token: T) -> Self {
        AccessToken(token.into())
    }
}

impl fmt::Display for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<secret-access-token>")
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AccessToken(<secret>)")
    }
}

/// An access token scope
///
/// See [RFC6749](https://tools.ietf.org/html/rfc6749#page-23)
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct Scope(pub String);

impl Scope {
    /// Creates a new `Scope`
    pub fn new<T: Into<String>>(scope: T) -> Scope {
        Scope(scope.into())
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Gives a `TokenInfo` for an `AccessToken`.
///
/// See [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
pub trait TokenInfoService {
    /// Gives a `TokenInfo` for an `AccessToken`.
    fn introspect(&self, token: &AccessToken) -> TokenInfoResult<TokenInfo>;
}

/// A `Result` where the failure is always an `InitializationError`
pub type InitializationResult<T> = ::std::result::Result<T, InitializationError>;

/// An error to be returned if the initialization of a component
/// or else fails.
#[derive(Debug, Fail)]
#[fail(display = "{}", _0)]
pub struct InitializationError(pub String);

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
    /// Use for authorization. Checks whether this `TokenInfo` has the given
    /// `Scope`.
    pub fn has_scope(&self, scope: &Scope) -> bool {
        self.scope.iter().find(|&s| s == scope).is_some()
    }

    /// Use for authorization. Checks whether this `TokenInfo` has all of the
    /// given `Scopes`.
    pub fn has_scopes(&self, scopes: &[Scope]) -> bool {
        scopes.iter().all(|scope| self.has_scope(scope))
    }

    /// If the `TokenInfo` does not have the scope this method will fail.
    pub fn must_have_scope(&self, scope: &Scope) -> ::std::result::Result<(), NotAuthorized> {
        if self.has_scope(scope) {
            Ok(())
        } else {
            Err(NotAuthorized(format!(
                "Required scope '{}' not present.",
                scope
            )))
        }
    }
}

/// There is no authorization for the requested resource
#[derive(Debug, Fail)]
pub struct NotAuthorized(pub String);

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
