//! # tokkit
//!
//! WORK IN PROGRESS
//!
//! `tokkit` is a simple(even simplistic) **tok**en tool**kit** for OAUTH2 authorization
//! targetting service to service authorization.
//!
//! ## Documentation
//!
//! The documentation is available [online](https://docs.rs/tokkit).
//!
//! ## Verify Access Tokens
//!
//! `tokkit` contains a module `token_info` for protected resources to verify access tokens.
//!
//! ```rust,no_run
//! use tokkit::*;
//! use tokkit::token_info::*;
//!
//! let builder = RemoteTokenInfoServiceBuilder::google_v3();
//! let service = builder.build().unwrap();
//!
//! let token = AccessToken::new("<token>");
//!
//! let tokeninfo = service.introspect(&token).unwrap();
//! ```
//!
//! ## Managing Tokens
//!
//! To be done....
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

#[macro_use]
extern crate error_chain;
extern crate json;
extern crate reqwest;
extern crate backoff;

pub mod token_info;
pub mod client;

use std::fmt;
use std::env::VarError;
use std::num::ParseFloatError;
use std::error::Error;

/// An access token
///
/// See [RFC6749](https://tools.ietf.org/html/rfc6749#page-10)
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
