use std::fmt;
use std::error::Error;

#[derive(Debug, Clone)]
pub enum AccessTokenProviderError {
    Client(String),
    Server(String),
    Connection(String),
    Parse(String),
    Credentials(super::credentials::CredentialsError),
    Other(String),
}

impl fmt::Display for AccessTokenProviderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AccessTokenProviderError::Client(ref msg) => write!(f, "Client error: {}", msg),
            AccessTokenProviderError::Server(ref msg) => write!(f, "Server error: {}", msg),
            AccessTokenProviderError::Connection(ref msg) => write!(f, "Connection error: {}", msg),
            AccessTokenProviderError::Parse(ref msg) => write!(f, "Parse error: {}", msg),
            AccessTokenProviderError::Credentials(ref inner) => {
                write!(f, "Problem with credentials caused by {}", inner)
            }
            AccessTokenProviderError::Other(ref msg) => write!(f, "Other error {}", msg),
        }
    }
}

impl Error for AccessTokenProviderError {
    fn description(&self) -> &str {
        match *self {
            AccessTokenProviderError::Client(_) => "the request to the token service was invalid",
            AccessTokenProviderError::Server(_) => "the token service returned an error",
            AccessTokenProviderError::Connection(_) => "the connection broke",
            AccessTokenProviderError::Parse(_) => {
                "the response from the token service couldn't be parsed"
            }
            AccessTokenProviderError::Credentials(_) => "problem with the credentials",
            AccessTokenProviderError::Other(_) => "something unexpected happened",
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            AccessTokenProviderError::Credentials(ref inner) => Some(inner),
            _ => None,
        }
    }
}

impl From<AccessTokenProviderError> for ::client::error::ErrorKind {
    fn from(what: AccessTokenProviderError) -> ::client::error::ErrorKind {
        ::client::error::ErrorKind::AccessTokenProvider(what)
    }
}

impl From<super::credentials::CredentialsError> for AccessTokenProviderError {
    fn from(what: super::credentials::CredentialsError) -> AccessTokenProviderError {
        AccessTokenProviderError::Credentials(what)
    }
}

impl From<::std::io::Error> for AccessTokenProviderError {
    fn from(what: ::std::io::Error) -> Self {
        AccessTokenProviderError::Connection(what.to_string())
    }
}

impl From<::std::str::Utf8Error> for AccessTokenProviderError {
    fn from(what: ::std::str::Utf8Error) -> Self {
        AccessTokenProviderError::Other(what.to_string())
    }
}
