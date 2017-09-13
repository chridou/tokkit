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
//! `tokkit` is a simple(even simplistic) **tok**en tool**kit** for OAUTH2 authorization
//! targetting service to service authorization.
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
//! ### Verify Access Tokens
//!
//! `tokkit` contains a module `token_info` for protected resources to verify access tokens.
//!
//! ```rust,no_run
//! use tokkit::*;
//! use tokkit::token_info::*;
//!
//! let builder = RemoteTokenInfoServiceBuilder::google_v3();
//!
//! let service = builder.build().unwrap();
//!
//! let token = AccessToken::new("<token>");
//!
//! let tokeninfo = service.introspect(&token).unwrap();
//! ```
//!
//! ### Managing Tokens
//!
//! `tokkit` can manage and automatically update your access tokens if you
//! are a client and want to access a resource owners resources.
//!
//! Currently `tokkit` only supports the
//! [Resource Owner Password Credentials Grant](https://tools.ietf.org/html/rfc6749#section-4.3)
//! which should only be used if the resource owner can really trust the client.
//!
//! ```rust,no_run
//! use tokkit::*;
//! use tokkit::token_manager::*;
//! use tokkit::token_manager::token_provider::*;
//! use tokkit::token_manager::token_provider::credentials::*;
//!
//! let credentials_provider = SplitFileCredentialsProvider::with_default_parsers_from_env()
//!     .unwrap();
//!
//! let token_provider =
//!     ResourceOwnerPasswordCredentialsGrantProvider
//!         ::from_env_with_credentials_provider(credentials_provider)
//!         .unwrap();
//!
//! let token_group =
//!     ManagedTokenGroupBuilder::single_token(
//!         "my_token_identifier",
//!         vec![Scope::new("read_my_diary")],
//!         token_provider)
//!     .build()
//!     .unwrap();
//!
//! let token_source = AccessTokenManager::start(vec![token_group]).unwrap();
//!
//! let access_token = token_source.get_access_token(&"my_token_identifier").unwrap();
//! ```
//!
//! ## License
//!
//! tokkit is primarily distributed under the terms of
//! both the MIT license and the Apache License (Version 2.0).
//!
//! Copyright (c) 2017 Christian Douven
#![recursion_limit = "1024"]

#[macro_use]
extern crate log;

extern crate backoff;
#[macro_use]
extern crate error_chain;
extern crate json;
extern crate reqwest;
extern crate url;

pub mod token_info;
pub mod token_manager;

use std::fmt;
use std::env::VarError;
use std::num::ParseFloatError;
use std::error::Error;

/// An access token
///
/// See [RFC6749](https://tools.ietf.org/html/rfc6749#section-1.4)
#[derive(Debug, Clone)]
pub struct AccessToken(pub String);

impl AccessToken {
    /// Creates a new `AccessToken`
    pub fn new<T: Into<String>>(token: T) -> Self {
        AccessToken(token.into())
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

/// A `Result` where the failure is always an `InitializationError`
pub type InitializationResult<T> = Result<T, InitializationError>;

/// An error to be returned if the initialization of a component
/// or else fails.
#[derive(Debug)]
pub struct InitializationError(pub String);

impl InitializationError {
    /// Creates a new InitializationError therby allocating a String.
    pub fn new<T: Into<String>>(message: T) -> InitializationError {
        InitializationError(message.into())
    }
}

impl fmt::Display for InitializationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Unauthorized: {}", self.0)
    }
}

impl Error for InitializationError {
    fn description(&self) -> &str {
        self.0.as_ref()
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}

impl From<VarError> for InitializationError {
    fn from(err: VarError) -> Self {
        InitializationError(format!("{}", err))
    }
}

impl From<ParseFloatError> for InitializationError {
    fn from(err: ParseFloatError) -> Self {
        InitializationError(format!("{}", err))
    }
}
