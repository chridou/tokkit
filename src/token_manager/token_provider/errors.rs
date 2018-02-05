use std::fmt;
use std::str;
use std::error::Error;

#[derive(Debug, Clone)]
pub enum AccessTokenProviderError {
    /// An invalid request was sent which contains further information.
    /// No retry necessary.
    BadAuthorizationRequest(AuthorizationRequestError),
    /// An error from the client side which does not fall under
    /// `BadAuthorizationRequest`.
    /// No retry necessary.
    Client(String),
    /// The authorization server itself had an error.
    /// Should be retried.
    Server(String),
    /// Something was wrong with the connection to the authorization server.
    /// Should be retried.
    Connection(String),
    /// A response could not be parsed. No retry necessary.
    Parse(String),
    /// The credentials could not be loaded. Maybe worth a retry.
    Credentials(super::credentials::CredentialsError),
    /// Something else happened. Most probably not worth a retry.
    Other(String),
}

/// An error in detail returned by the authorization server.
///
/// See [RFC6749 sec. 5.2](https://tools.ietf.org/html/rfc6749#section-5.2)
#[derive(Debug, Clone)]
pub struct AuthorizationRequestError {
    /// The error code returned from the authorization server
    ///
    /// See [RFC6749 sec. 5.2](https://tools.ietf.org/html/rfc6749#section-5.2)
    pub error: AuthorizationServerErrorCode,
    /// Human-readable ASCII [USASCII] text providing
    /// additional information, used to assist the client developer in
    /// understanding the error that occurred.
    /// Values for the "error_description" parameter MUST NOT include
    /// characters outside the set %x20-21 / %x23-5B / %x5D-7E.
    ///
    /// See [RFC6749 sec. 5.2](https://tools.ietf.org/html/rfc6749#section-5.2)
    pub error_description: Option<String>,
    /// A URI identifying a human-readable web page with
    /// information about the error, used to provide the client
    /// developer with additional information about the error.
    /// Values for the "error_uri" parameter MUST conform to the
    /// URI-reference syntax and thus MUST NOT include characters
    /// outside the set %x21 / %x23-5B / %x5D-7E.
    ///
    /// See [RFC6749 sec. 5.2](https://tools.ietf.org/html/rfc6749#section-5.2)
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

impl str::FromStr for AuthorizationServerErrorCode {
    type Err = AccessTokenProviderError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "invalid_request" => Ok(AuthorizationServerErrorCode::InvalidRequest),
            "invalid_client" => Ok(AuthorizationServerErrorCode::InvalidClient),
            "invalid_grant" => Ok(AuthorizationServerErrorCode::InvalidGrant),
            "unauthorized_client" => Ok(AuthorizationServerErrorCode::UnauthorizedClient),
            "unsupported_grant_type" => Ok(AuthorizationServerErrorCode::UnsupportedGrantType),
            "invalid_scope" => Ok(AuthorizationServerErrorCode::InvalidScope),
            x => Err(AccessTokenProviderError::Other(format!(
                "'{}' is not a valid error kind.",
                x
            ))),
        }
    }
}

/// The error code returned from the authorization server on
/// `BadRequest`.
#[derive(Debug, Clone)]
pub enum AuthorizationServerErrorCode {
    /// The request is missing a required parameter, includes an
    /// unsupported parameter value (other than grant type),
    /// repeats a parameter, includes multiple credentials,
    /// utilizes more than one mechanism for authenticating the
    /// client, or is otherwise malformed.
    InvalidRequest,
    /// Client authentication failed (e.g., unknown client, no
    /// client authentication included, or unsupported
    /// authentication method).  The authorization server MAY
    /// return an HTTP 401 (Unauthorized) status code to indicate
    /// which HTTP authentication schemes are supported.  If the
    /// client attempted to authenticate via the "Authorization"
    /// request header field, the authorization server MUST
    /// respond with an HTTP 401 (Unauthorized) status code and
    /// include the "WWW-Authenticate" response header field
    /// matching the authentication scheme used by the client.
    InvalidClient,
    /// The provided authorization grant (e.g., authorization
    /// code, resource owner credentials) or refresh token is
    /// invalid, expired, revoked, does not match the redirection
    /// URI used in the authorization request, or was issued to
    /// another client.
    InvalidGrant,
    /// The authenticated client is not authorized to use this
    /// authorization grant type.
    UnauthorizedClient,
    /// The authorization grant type is not supported by the
    /// authorization server.
    UnsupportedGrantType,
    /// The requested scope is invalid, unknown, malformed, or
    /// exceeds the scope granted by the resource owner.
    InvalidScope,
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
