use std::sync::Arc;
use std::io::Read;
use reqwest::{Url, Client, StatusCode, UrlError};
use resource_server::*;

struct RemoteAuthorizationServer {
    url: Arc<String>,
    fallback_url: Arc<Option<String>>,
    query_parameter: String,
    http_client: Client,
}

impl AuthorizationServer for RemoteAuthorizationServer {
    fn authenticate(&self, token: &Token) -> Result<AuthenticatedUser> {
        let url: Url = make_url(&self.url, &self.query_parameter, token)?;
        let fallback_url = match *self.fallback_url {
            Some(ref fb_url) => Some(make_url(fb_url, &self.query_parameter, token)?),
            None => None,
        };
        get_with_fallback(token, url, fallback_url, &self.http_client)
    }
}

impl Clone for RemoteAuthorizationServer {
    fn clone(&self) -> Self {
        RemoteAuthorizationServer {
            url: self.url.clone(),
            fallback_url: self.fallback_url.clone(),
            query_parameter: self.query_parameter.clone(),
            http_client: self.http_client.clone(),
        }
    }
}

fn make_url(url: &str, query_parameter: &str, token: &Token) -> Result<Url> {
    let url_str = format!("{}?{}={}", url, query_parameter, token.0);
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
