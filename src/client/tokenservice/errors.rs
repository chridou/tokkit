use std::fmt;

#[derive(Debug, Clone)]
pub enum TokenServiceError {
    Client(String),
    Server(String),
    Connection(String),
    Other(String),
}

impl fmt::Display for TokenServiceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TokenServiceError::Client(ref msg) => write!(f, "Client error: {}", msg),
            TokenServiceError::Server(ref msg) => write!(f, "Server error: {}", msg),
            TokenServiceError::Connection(ref msg) => write!(f, "Connection error: {}", msg),
            TokenServiceError::Other(ref msg) => write!(f, "Other error {}", msg),
        }

    }
}

impl From<TokenServiceError> for ::client::error::ErrorKind {
    fn from(what: TokenServiceError) -> ::client::error::ErrorKind {
        ::client::error::ErrorKind::TokenService(what)
    }
}
