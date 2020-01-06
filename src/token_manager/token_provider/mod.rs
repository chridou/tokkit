//! Interaction with the authorization server
use std::env::{self, VarError};
use std::io::Read;
use std::result::Result as StdResult;
use std::str;
use std::time::Duration;

use json;
use json::*;
use reqwest::header::*;
use reqwest::{Error as RError, StatusCode};
use reqwest::blocking::{Client, Response};
use url::form_urlencoded;

use self::credentials::{CredentialsProvider, RequestTokenCredentials};
pub use self::errors::*;
use super::*;

pub mod credentials;
mod errors;

pub type AccessTokenProviderResult =
    StdResult<AuthorizationServerResponse, AccessTokenProviderError>;

/// The response an `AccessTokenProvider` received from an authorization server.
pub struct AuthorizationServerResponse {
    pub access_token: AccessToken,
    pub expires_in: Duration,
    pub refresh_token: Option<String>,
}

/// Calls an authorization server for an `AccessToken` and the
/// time left until the `AccessToken` expires.
///
/// Implementors may use different flows to interact with the
/// authorization server.
pub trait AccessTokenProvider {
    /// Issue a request to the authorization server for an `AccessToken`
    /// with the given `Scope`s.
    fn request_access_token(&self, scopes: &[Scope]) -> AccessTokenProviderResult;
}

/// Provides tokens via Resource Owner Password Credentials Grant
///
/// See [RFC6749 Sec. 4.4](https://tools.ietf.org/html/rfc6749#section-4.3)
pub struct ResourceOwnerPasswordCredentialsGrantProvider {
    full_endpoint_url: String,
    client: Client,
    credentials_provider: Box<CredentialsProvider + Send + Sync + 'static>,
}

impl ResourceOwnerPasswordCredentialsGrantProvider {
    pub fn new<U, C>(
        endpoint_url: U,
        credentials_provider: C,
        realm: Option<&str>,
    ) -> InitializationResult<Self>
    where
        U: Into<String>,
        C: CredentialsProvider + Send + Sync + 'static,
    {
        let client = Client::new();
        let mut full_endpoint_url = endpoint_url.into();
        if let Some(realm) = realm {
            full_endpoint_url.push_str("?realm=");
            full_endpoint_url.push_str(realm);
        }
        Ok(ResourceOwnerPasswordCredentialsGrantProvider {
            full_endpoint_url: full_endpoint_url,
            client: client,
            credentials_provider: Box::new(credentials_provider),
        })
    }

    /// Creates a new instance from the given `CredentialsProvider`
    /// and gets the remaining values from environment variables.
    ///
    /// Environment variables:
    ///
    /// * '´TOKKIT_AUTHORIZATION_SERVER_URL´': URL of the endpoint to send the
    /// token request to * '´TOKKIT_AUTHORIZATION_SERVER_REALM´': An
    /// optional Realm passed as a URL parameter
    pub fn from_env_with_credentials_provider<C>(
        credentials_provider: C,
    ) -> InitializationResult<Self>
    where
        C: CredentialsProvider + Send + Sync + 'static,
    {
        let endpoint_url: String = match env::var("TOKKIT_AUTHORIZATION_SERVER_URL") {
            Ok(url) => url.into(),
            Err(VarError::NotPresent) => {
                return Err(InitializationError(
                    "'TOKKIT_AUTHORIZATION_SERVER_URL' not found.".to_string(),
                ))
            }
            Err(err) => return Err(InitializationError(err.to_string())),
        };

        let realm: Option<String> = match env::var("TOKKIT_AUTHORIZATION_SERVER_REALM") {
            Ok(realm) => Some(realm.into()),
            Err(VarError::NotPresent) => None,
            Err(err) => return Err(InitializationError(err.to_string())),
        };

        ResourceOwnerPasswordCredentialsGrantProvider::new(
            endpoint_url,
            credentials_provider,
            realm.as_ref().map(|x| &**x),
        )
    }
}

impl AccessTokenProvider for ResourceOwnerPasswordCredentialsGrantProvider {
    fn request_access_token(&self, scopes: &[Scope]) -> AccessTokenProviderResult {
        let credentials = self.credentials_provider.credentials()?;
        match execute_access_token_request(
            &self.client,
            &self.full_endpoint_url,
            scopes,
            credentials,
        ) {
            Ok(mut rsp) => evaluate_response(&mut rsp),
            Err(err) => Err(AccessTokenProviderError::Connection(err.to_string())),
        }
    }
}

fn evaluate_response(rsp: &mut Response) -> AccessTokenProviderResult {
    let status = rsp.status().clone();
    let mut body = Vec::new();
    rsp.read_to_end(&mut body)?;
    match status {
        StatusCode::OK => parse_response(&body, None),
        StatusCode::BAD_REQUEST => Err(AccessTokenProviderError::BadAuthorizationRequest(
            parse_error(&body)?,
        )),
        _ if status.is_client_error() => {
            let body = str::from_utf8(&body)?;
            Err(AccessTokenProviderError::Server(format!(
                "The request sent to the authorization server was faulty({}): {}",
                status, body
            )))
        }
        _ if status.is_server_error() => {
            let body = str::from_utf8(&body)?;
            Err(AccessTokenProviderError::Server(format!(
                "The authorization server returned an error({}): {}",
                status, body
            )))
        }
        _ => {
            let body = str::from_utf8(&body)?;
            Err(AccessTokenProviderError::Client(format!(
                "Received unexpected status code({}) from authorization server: {}",
                status, body
            )))
        }
    }
}

fn execute_access_token_request(
    client: &Client,
    full_url: &str,
    scopes: &[Scope],
    credentials: RequestTokenCredentials,
) -> StdResult<Response, RError> {
    let request_builder = client
        .post(full_url)
        .header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        ).basic_auth(
            credentials.client_credentials.client_id,
            Some(credentials.client_credentials.client_secret),
        );

    let mut scope_vec = Vec::new();

    for scope in scopes {
        scope_vec.push(scope.0.clone());
    }

    let form_encoded = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "password")
        .append_pair("username", &credentials.owner_credentials.username)
        .append_pair("password", &credentials.owner_credentials.password)
        .append_pair("scope", &scope_vec.join(" "))
        .finish();

    let rsp = request_builder.body(form_encoded).send()?;

    Ok(rsp)
}

fn parse_response(bytes: &[u8], default_expires_in: Option<Duration>) -> AccessTokenProviderResult {
    let json_utf8 =
        str::from_utf8(bytes).map_err(|err| AccessTokenProviderError::Parse(err.to_string()))?;
    let json =
        json::parse(json_utf8).map_err(|err| AccessTokenProviderError::Parse(err.to_string()))?;

    if let JsonValue::Object(data) = json {
        let access_token = match data.get("access_token") {
            Some(&JsonValue::Short(user_id)) => user_id.to_string(),
            Some(&JsonValue::String(ref user_id)) => user_id.clone(),
            _ => {
                return Err(AccessTokenProviderError::Parse(
                    "Expected a string as the access token but found something else".to_string(),
                ))
            }
        };

        let expires_in: Duration = match data.get("expires_in") {
            Some(&JsonValue::Number(expires_in)) => {
                if let Some(expires_in) = expires_in.as_fixed_point_u64(0) {
                    Duration::from_secs(expires_in)
                } else {
                    return Err(AccessTokenProviderError::Parse(
                        "'expires in must fit into an u64'".to_string(),
                    ));
                }
            }
            None => {
                if let Some(default_expires_in) = default_expires_in {
                    default_expires_in
                } else {
                    return Err(AccessTokenProviderError::Parse(
                        "No field 'expires_in' found and no default".to_string(),
                    ));
                }
            }
            invalid => {
                return Err(AccessTokenProviderError::Parse(format!(
                    "Expected a number as 'expires_in' but found a {:?}",
                    invalid
                )))
            }
        };

        let refresh_token = match data.get("refresh_token") {
            Some(&JsonValue::Short(refresh_token)) => Some(refresh_token.to_string()),
            Some(&JsonValue::String(ref refresh_token)) => Some(refresh_token.clone()),
            None => None,
            _ => {
                return Err(AccessTokenProviderError::Parse(
                    "Expected a string as the refresh token but found something else".to_string(),
                ))
            }
        };

        Ok(AuthorizationServerResponse {
            access_token: AccessToken::new(access_token),
            expires_in,
            refresh_token,
        })
    } else {
        return Err(AccessTokenProviderError::Parse(
            "Token service response is not a JSON object".to_string(),
        ));
    }
}

fn parse_error(bytes: &[u8]) -> StdResult<AuthorizationRequestError, AccessTokenProviderError> {
    let json_utf8 =
        str::from_utf8(bytes).map_err(|err| AccessTokenProviderError::Parse(err.to_string()))?;
    let json =
        json::parse(json_utf8).map_err(|err| AccessTokenProviderError::Parse(err.to_string()))?;

    if let JsonValue::Object(data) = json {
        let error = match data.get("error") {
            Some(&JsonValue::Short(kind)) => kind.parse()?,
            Some(&JsonValue::String(ref kind)) => kind.parse()?,
            _ => {
                return Err(AccessTokenProviderError::Parse(
                    "Expected a string as the error but found something else".to_string(),
                ))
            }
        };

        let error_description = match data.get("error_description") {
            Some(&JsonValue::Short(error_description)) => Some(error_description.to_string()),
            Some(&JsonValue::String(ref error_description)) => Some(error_description.clone()),
            None => None,
            _ => {
                return Err(AccessTokenProviderError::Parse(
                    "Expected a string as the error_description but found something else"
                        .to_string(),
                ))
            }
        };

        let error_uri = match data.get("error_uri") {
            Some(&JsonValue::Short(error_uri)) => Some(error_uri.to_string()),
            Some(&JsonValue::String(ref error_uri)) => Some(error_uri.clone()),
            None => None,
            _ => {
                return Err(AccessTokenProviderError::Parse(
                    "Expected a string as the error_uri but found something else".to_string(),
                ))
            }
        };

        Ok(AuthorizationRequestError {
            error,
            error_description,
            error_uri,
        })
    } else {
        return Err(AccessTokenProviderError::Parse(
            "The response is not a JSON object".to_string(),
        ));
    }
}

/// Provides access tokens from an environment variable
///
/// The name of the environment variable can be configured as well
/// as the time after which the token expires.
pub struct EnvAccessTokenProvider {
    env_var_name: String,
    expires_in: Duration,
}

impl EnvAccessTokenProvider {
    /// Create a new `EnvAccessTokenProvider` that reads a token from the
    /// environment variable named `env_var_name`.
    ///
    /// It always has the queried `Scope`s and always expires after
    /// `expires_in`.
    pub fn new<T: Into<String>>(
        env_var_name: T,
        expires_in: Duration,
    ) -> InitializationResult<Self> {
        let env_var_name = env_var_name.into();

        if env_var_name.is_empty() {
            Err(InitializationError(
                "'env_var_name' may not be empty".into(),
            ))
        } else {
            Ok(EnvAccessTokenProvider {
                env_var_name,
                expires_in,
            })
        }
    }
}

impl AccessTokenProvider for EnvAccessTokenProvider {
    fn request_access_token(&self, _scopes: &[Scope]) -> AccessTokenProviderResult {
        let access_token = match env::var(&self.env_var_name) {
            Ok(token) => AccessToken::new(token),
            Err(err) => {
                return Err(AccessTokenProviderError::Other(format!(
                    "Could not get token from env var '{}': {}",
                    self.env_var_name, err
                )))
            }
        };

        let response = AuthorizationServerResponse {
            access_token,
            expires_in: self.expires_in,
            refresh_token: None,
        };

        Ok(response)
    }
}
