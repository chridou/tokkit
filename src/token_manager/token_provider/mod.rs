//! Interaction with the authorization server
use std::str;
use std::time::Duration;
use std::result::Result as StdResult;
use std::io::Read;
use std::env::{self, VarError};

use reqwest::{Client, Error as RError, Response, StatusCode};
use reqwest::header;
use url::form_urlencoded;
use json;
use json::*;

use super::*;
use self::credentials::{CredentialsProvider, RequestTokenCredentials};
pub use self::errors::*;

mod errors;
pub mod credentials;

pub type AccessTokenProviderResult = StdResult<
    AuthorizationServerResponse,
    AccessTokenProviderError,
>;

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
        let client = Client::new().map_err(
            |err| InitializationError(format!("{}", err)),
        )?;
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
    /// * '´TOKKIT_AUTHORIZATION_SERVER_URL´': URL of the endpoint to send the token request to
    /// * '´TOKKIT_AUTHORIZATION_SERVER_REALM´': An optional Realm passed as a URL parameter
    pub fn from_env_with_credentials_provider<C>(
        credentials_provider: C,
    ) -> InitializationResult<Self>
    where
        C: CredentialsProvider + Send + Sync + 'static,
    {
        let endpoint_url: String = match env::var("TOKKIT_AUTHORIZATION_SERVER_URL") {
            Ok(url) => url.into(),
            Err(VarError::NotPresent) => {
                bail!(InitializationError(
                    "'TOKKIT_AUTHORIZATION_SERVER_URL' not found.".to_string(),
                ))
            }
            Err(err) => bail!(err),
        };

        let realm: Option<String> = match env::var("TOKKIT_AUTHORIZATION_SERVER_REALM") {
            Ok(realm) => Some(realm.into()),
            Err(VarError::NotPresent) => None,
            Err(err) => bail!(err),
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
        StatusCode::Ok => parse_response(&body, None),
        StatusCode::BadRequest => Err(AccessTokenProviderError::BadAuthorizationRequest(
            parse_error(&body)?,
        )),
        _ if status.is_client_error() => {
            let body = str::from_utf8(&body)?;
            Err(AccessTokenProviderError::Server(format!(
                "The request sent to the authorization server was faulty({}): {}",
                status,
                body
            )))
        }
        _ if status.is_server_error() => {
            let body = str::from_utf8(&body)?;
            Err(AccessTokenProviderError::Server(format!(
                "The authorization server returned an error({}): {}",
                status,
                body
            )))
        }
        _ => {
            let body = str::from_utf8(&body)?;
            Err(AccessTokenProviderError::Client(format!(
                "Received unexpected status code({}) from authorization server: {}",
                status,
                body
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
    let mut headers = header::Headers::new();
    let mut scope_vec = Vec::new();
    for scope in scopes {
        scope_vec.push(scope.0.clone());
    }
    headers.set(header::Authorization(header::Basic {
        username: credentials.client_credentials.client_id.clone(),
        password: Some(credentials.client_credentials.client_secret.clone()),
    }));
    headers.set(header::ContentType::form_url_encoded());
    let form_encoded = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "password")
        .append_pair("username", &credentials.owner_credentials.username)
        .append_pair("password", &credentials.owner_credentials.password)
        .append_pair("scope", &scope_vec.join(" "))
        .finish();

    let mut request_builder = client.post(full_url)?;
    request_builder.headers(headers).body(form_encoded);
    let rsp = request_builder.send()?;
    Ok(rsp)
}


fn parse_response(bytes: &[u8], default_expires_in: Option<Duration>) -> AccessTokenProviderResult {
    let json_utf8 = str::from_utf8(bytes).map_err(|err| {
        AccessTokenProviderError::Parse(err.to_string())
    })?;
    let json = json::parse(json_utf8).map_err(|err| {
        AccessTokenProviderError::Parse(err.to_string())
    })?;

    if let JsonValue::Object(data) = json {
        let access_token = match data.get("access_token") {
            Some(&JsonValue::Short(user_id)) => user_id.to_string(),
            Some(&JsonValue::String(ref user_id)) => user_id.clone(),
            _ => {
                bail!(AccessTokenProviderError::Parse(
                    "Expected a string as the access token but found something else"
                        .to_string(),
                ))
            }
        };

        let expires_in: Duration = match data.get("expires_in") {
            Some(&JsonValue::Number(expires_in)) => {
                if let Some(expires_in) = expires_in.as_fixed_point_u64(0) {
                    Duration::from_secs(expires_in)
                } else {
                    bail!(AccessTokenProviderError::Parse(
                        "'expires in must fit into an u64'".to_string(),
                    ))
                }
            }
            None => {
                if let Some(default_expires_in) = default_expires_in {
                    default_expires_in
                } else {
                    bail!(AccessTokenProviderError::Parse(
                        "No field 'expires_in' found and no default".to_string(),
                    ))
                }
            }
            invalid => {
                bail!(AccessTokenProviderError::Parse(format!(
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
                bail!(AccessTokenProviderError::Parse(
                    "Expected a string as the refresh token but found something else"
                        .to_string(),
                ))
            }
        };

        Ok(AuthorizationServerResponse {
            access_token: AccessToken::new(access_token),
            expires_in,
            refresh_token,
        })
    } else {
        bail!(AccessTokenProviderError::Parse(
            "Token service response is not a JSON object".to_string(),
        ))
    }
}

fn parse_error(bytes: &[u8]) -> StdResult<AuthorizationRequestError, AccessTokenProviderError> {
    let json_utf8 = str::from_utf8(bytes).map_err(|err| {
        AccessTokenProviderError::Parse(err.to_string())
    })?;
    let json = json::parse(json_utf8).map_err(|err| {
        AccessTokenProviderError::Parse(err.to_string())
    })?;

    if let JsonValue::Object(data) = json {
        let error = match data.get("error") {
            Some(&JsonValue::Short(kind)) => kind.parse()?,
            Some(&JsonValue::String(ref kind)) => kind.parse()?,
            _ => {
                bail!(AccessTokenProviderError::Parse(
                    "Expected a string as the error but found something else"
                        .to_string(),
                ))
            }
        };

        let error_description = match data.get("error_description") {
            Some(&JsonValue::Short(error_description)) => Some(error_description.to_string()),
            Some(&JsonValue::String(ref error_description)) => Some(error_description.clone()),
            None => None,
            _ => {
                bail!(AccessTokenProviderError::Parse(
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
                bail!(AccessTokenProviderError::Parse(
                    "Expected a string as the error_uri but found something else"
                        .to_string(),
                ))
            }
        };

        Ok(AuthorizationRequestError {
            error,
            error_description,
            error_uri,
        })
    } else {
        bail!(AccessTokenProviderError::Parse(
            "The response is not a JSON object".to_string(),
        ))
    }
}
