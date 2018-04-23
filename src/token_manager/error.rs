use std::fmt;

use failure::*;

pub type TokenResult<T> = ::std::result::Result<T, TokenError>;

#[derive(Debug)]
pub struct TokenError {
    inner: Context<TokenErrorKind>,
}

impl TokenError {
    pub fn kind(&self) -> &TokenErrorKind {
        &self.inner.get_context()
    }
}

impl Fail for TokenError {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl From<TokenErrorKind> for TokenError {
    fn from(kind: TokenErrorKind) -> TokenError {
        TokenError {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<TokenErrorKind>> for TokenError {
    fn from(inner: Context<TokenErrorKind>) -> TokenError {
        TokenError { inner: inner }
    }
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

#[derive(Debug, Clone, Fail)]
pub enum TokenErrorKind {
    #[fail(display = "{}", _0)]
    NoToken(String),
    /// The token with the given identifier is not yet initialized
    #[fail(display = "{}", _0)]
    NotInitialized(String),
    /// An error from the `AccessTokenProvider`
    #[fail(display = "{}", _0)]
    AccessTokenProvider(String),
}
