use std::fmt;

use failure::*;

pub type TokenInfoResult<T> = ::std::result::Result<T, TokenInfoError>;

#[derive(Debug)]
pub struct TokenInfoError {
    inner: Context<TokenInfoErrorKind>,
}

impl TokenInfoError {
    pub fn kind(&self) -> &TokenInfoErrorKind {
        &self.inner.get_context()
    }

    pub fn is_retry_suggested(&self) -> bool {
        use TokenInfoErrorKind::*;
        match *self.kind() {
            InvalidResponseContent(_) => false,
            UrlError(_) => false,
            NotAuthenticated(_) => false,
            Connection(_) => true,
            Io(_) => true,
            Client(_) => false,
            Server(_) => true,
            Other(_) => true,
            BudgetExceeded => false,
        }
    }
}

impl Fail for TokenInfoError {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl From<TokenInfoErrorKind> for TokenInfoError {
    fn from(kind: TokenInfoErrorKind) -> TokenInfoError {
        TokenInfoError {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<TokenInfoErrorKind>> for TokenInfoError {
    fn from(inner: Context<TokenInfoErrorKind>) -> TokenInfoError {
        TokenInfoError { inner: inner }
    }
}

impl fmt::Display for TokenInfoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

#[derive(Debug, Clone, Fail)]
pub enum TokenInfoErrorKind {
    #[fail(display = "{}", _0)]
    InvalidResponseContent(String),
    #[fail(display = "{}", _0)]
    UrlError(String),
    #[fail(display = "{}", _0)]
    NotAuthenticated(String),
    #[fail(display = "{}", _0)]
    Connection(String),
    #[fail(display = "{}", _0)]
    Io(String),
    #[fail(display = "{}", _0)]
    Client(String),
    #[fail(display = "{}", _0)]
    Server(String),
    #[fail(display = "{}", _0)]
    Other(String),
    #[fail(display = "Request budget on tokenintrospection service exceeded")]
    BudgetExceeded,
}
