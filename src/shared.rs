use std::fmt;
use std::env::VarError;
use std::num::ParseFloatError;
use std::error::Error;

/// An access token
///
/// See [RFC6749](https://tools.ietf.org/html/rfc6749#page-10)
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
