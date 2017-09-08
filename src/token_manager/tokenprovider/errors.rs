use std::fmt;
use std::str;
use std::error::Error;

#[derive(Debug, Clone)]
pub enum AccessTokenProviderError {
    /// An invalid request was sent which contains further information.
    BadAuthorizationRequest(AuthorizationRequestError),
    Client(String),
    Server(String),
    Connection(String),
    Parse(String),
    Credentials(super::credentials::CredentialsError),
    Other(String),
}

#[derive(Debug, Clone)]
pub struct AuthorizationRequestError {
    pub error: AuthorizationRequestErrorKind,
    pub error_description: Option<String>,
    pub error_uri: Option<String>,
}

impl fmt::Display for AuthorizationRequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut error_msg = format!(
            "An invalid request was sent to the authorization server. \
             The error is \"{:?}\".",
            self.error,
        );
        if let Some(ref msg) = self.error_description {
            error_msg.push_str(&format!(" The message from the server is \"{}\".", msg));
        }
        if let Some(ref uri) = self.error_uri {
            error_msg.push_str(&format!(" You can find more information at \"{}\".", uri));
        }
        write!(f, "{}", error_msg)
    }
}

impl str::FromStr for AuthorizationRequestErrorKind {
    type Err = AccessTokenProviderError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "invalid_request" => Ok(AuthorizationRequestErrorKind::InvalidRequest),
            "invalid_client" => Ok(AuthorizationRequestErrorKind::InvalidClient),
            "invalid_grant" => Ok(AuthorizationRequestErrorKind::InvalidGrant),
            "unauthorized_client" => Ok(AuthorizationRequestErrorKind::UnauthorizedClient),
            "unsupported_grant_type" => Ok(AuthorizationRequestErrorKind::UnsupportedGrantType),
            x => Err(AccessTokenProviderError::Other(
                format!("'{}' is not a valid error kind.", x),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub enum AuthorizationRequestErrorKind {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
}

impl fmt::Display for AccessTokenProviderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AccessTokenProviderError::BadAuthorizationRequest(ref err) => {
                write!(f, "Bad authorization request: {}", err)
            }
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
            AccessTokenProviderError::BadAuthorizationRequest(_) => {
                "an invalid request was sent to the authorization server"
            }
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

impl From<AccessTokenProviderError> for ::token_manager::error::ErrorKind {
    fn from(what: AccessTokenProviderError) -> ::token_manager::error::ErrorKind {
        ::token_manager::error::ErrorKind::AccessTokenProvider(what)
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
