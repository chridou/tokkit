use std::fmt;
use std::env::VarError;
use std::num::ParseFloatError;
use std::error::Error;

pub struct Token(pub String);

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct Scope(pub String);

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An error to be returned if the initialization of a component fails.
#[derive(Debug)]
pub struct InitializationError {
    pub message: String,
}

impl InitializationError {
    /// Creates a new InitializationError therby allocating a String.
    pub fn new<T: Into<String>>(message: T) -> InitializationError {
        InitializationError { message: message.into() }
    }
}

impl fmt::Display for InitializationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Unauthorized: {}", self.message)
    }
}

impl Error for InitializationError {
    fn description(&self) -> &str {
        self.message.as_ref()
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}

impl From<VarError> for InitializationError {
    fn from(err: VarError) -> Self {
        InitializationError { message: format!{"{}", err} }
    }
}

impl From<ParseFloatError> for InitializationError {
    fn from(err: ParseFloatError) -> Self {
        InitializationError { message: format!{"{}", err} }
    }
}
