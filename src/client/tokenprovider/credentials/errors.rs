use std::fmt;
use std::error::Error;

pub type CredentialsResult<T> = Result<T, CredentialsError>;

#[derive(Debug, Clone)]
pub enum CredentialsError {
    Parse(String),
    Io(String),
    Other(String),
}

impl fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CredentialsError::Parse(ref msg) => write!(f, "Could not parse credentials: {}", msg),
            CredentialsError::Io(ref msg) => write!(f, "Io error: {}", msg),
            CredentialsError::Other(ref msg) => write!(f, "Other error {}", msg),
        }
    }
}

impl Error for CredentialsError {
    fn description(&self) -> &str {
        match *self {
            CredentialsError::Parse(_) => "could not parse the credentials",
            CredentialsError::Io(_) => "io error",
            CredentialsError::Other(_) => "something unexpected happened",
        }
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}

impl From<::std::io::Error> for CredentialsError {
    fn from(err: ::std::io::Error) -> Self {
        CredentialsError::Io(err.to_string())
    }
}
