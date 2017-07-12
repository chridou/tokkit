use std::sync::Arc;
use std::io::Read;
use std::env;
use reqwest::{Url, Client, StatusCode, UrlError};
use resource_server::*;

struct RemoteAuthorizationServer {
    url_prefix: Arc<String>,
    fallback_url_prefix: Arc<Option<String>>,
    http_client: Client,
}

impl RemoteAuthorizationServer {
    pub fn new(
        endpoint: &str,
        query_parameter: &str,
    ) -> ::std::result::Result<RemoteAuthorizationServer, InitializationError> {
        RemoteAuthorizationServer::new_with_fallback(endpoint, query_parameter, None)
    }

    pub fn new_with_fallback(
        endpoint: &str,
        query_parameter: &str,
        fallback_endpoint: Option<&str>,
    ) -> ::std::result::Result<RemoteAuthorizationServer, InitializationError> {
        let url_prefix = format!("{}?{}=", endpoint, query_parameter);
        format!("{}test-token", url_prefix).parse::<Url>().map_err(
            |err| {
                InitializationError(err.to_string())
            },
        )?;

        let fallback_url_prefix = if let Some(fallback_endpoint_address) = fallback_endpoint {
            let url_prefix = format!("{}?{}=", fallback_endpoint_address, query_parameter);
            format!("{}test-fallback-token", url_prefix)
                .parse::<Url>()
                .map_err(|err| InitializationError(err.to_string()))?;
            Some(url_prefix)
        } else {
            None
        };

        let client = Client::new().map_err(
            |err| InitializationError(err.to_string()),
        )?;
        Ok(RemoteAuthorizationServer {
            url_prefix: Arc::new(url_prefix),
            fallback_url_prefix: Arc::new(fallback_url_prefix),
            http_client: client,
        })
    }

    pub fn from_env() -> ::std::result::Result<RemoteAuthorizationServer, InitializationError> {
        let endpoint = env::var("TOKKIT_AUTH_ENDPOINT").map_err(|err| {
            InitializationError(format!("'TOKKIT_AUTH_ENDPOINT':{}", err))
        })?;
        let query_parameter = env::var("TOKKIT_AUTH_QUERY_PARAMETER").map_err(|err| {
            InitializationError(format!("'TOKKIT_AUTH_QUERY_PARAMETER':{}", err))
        })?;
        let fallback_endpoint = match env::var("TOKKIT_AUTH_ENDPOINT_FALLBACK") {
            Ok(v) => Some(v),
            Err(env::VarError::NotPresent) => None,
            Err(err) => {
                return Err(InitializationError(err.to_string())).map_err(|err| {
                    InitializationError(format!("'TOKKIT_AUTH_ENDPOINT_FALLBACK':{}", err))
                })
            }
        };
        RemoteAuthorizationServer::new_with_fallback(
            &endpoint,
            &query_parameter,
            fallback_endpoint.as_ref().map(|x| &**x),
        )
    }
}

impl AuthorizationServer for RemoteAuthorizationServer {
    fn authenticate(&self, token: &Token) -> Result<AuthenticatedUser> {
        let url: Url = complete_url(&self.url_prefix, token)?;
        let fallback_url = match *self.fallback_url_prefix {
            Some(ref fb_url_prefix) => Some(complete_url(fb_url_prefix, token)?),
            None => None,
        };
        get_with_fallback(token, url, fallback_url, &self.http_client)
    }
}

impl Clone for RemoteAuthorizationServer {
    fn clone(&self) -> Self {
        RemoteAuthorizationServer {
            url_prefix: self.url_prefix.clone(),
            fallback_url_prefix: self.fallback_url_prefix.clone(),
            http_client: self.http_client.clone(),
        }
    }
}

fn complete_url(url_prefix: &str, token: &Token) -> Result<Url> {
    let mut url_str = url_prefix.to_string();
    url_str.push_str(token.0.as_ref());
    let url = url_str.parse()?;
    Ok(url)
}

fn get_with_fallback(
    token: &Token,
    url: Url,
    fallback_url: Option<Url>,
    client: &Client,
) -> Result<AuthenticatedUser> {
    get_remote(token, url, client).or_else(|err| match err {
        Error(ErrorKind::ClientError(_, _), _) => Err(err),
        _ => {
            fallback_url
                .map(|url| get_remote(token, url, client))
                .unwrap_or(Err(err))
        }
    })
}

fn get_remote(token: &Token, url: Url, http_client: &Client) -> Result<AuthenticatedUser> {
    match http_client.get(url).send() {
        Ok(mut response) => {
            let mut body = String::new();
            response.read_to_string(&mut body)?;
            if *response.status() == StatusCode::Ok {
                super::json_to_user(&body)
            } else if *response.status() == StatusCode::Unauthorized {
                bail!(ErrorKind::NotAuthenticated(body))
            } else if response.status().is_client_error() {
                bail!(ErrorKind::ClientError(response.status().to_string(), body))
            } else if response.status().is_server_error() {
                bail!(ErrorKind::ServerError(response.status().to_string(), body))
            } else {
                bail!(format!(
                    "Unexpected response with status {}: {}",
                    response.status(),
                    body
                ))
            }
        }
        Err(err) => Err(ErrorKind::Connection(err.to_string()).into()),
    }
}

impl From<UrlError> for Error {
    fn from(what: UrlError) -> Self {
        ErrorKind::UrlError(what.to_string()).into()
    }
}
