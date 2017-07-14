use std::sync::Arc;
use std::io::Read;
use std::env;
use std::str;
use reqwest::{Url, Client, StatusCode, UrlError, Response};
use token_info::*;

struct TokenInfoServer {
    url_prefix: Arc<String>,
    fallback_url_prefix: Option<Arc<String>>,
    http_client: Client,
    parser: Arc<TokenInfoParser>,
}

impl TokenInfoServer {
    pub fn new<P>(
        endpoint: &str,
        query_parameter: Option<&str>,
        parser: P,
    ) -> ::std::result::Result<TokenInfoServer, InitializationError>
    where
        P: TokenInfoParser,
    {
        TokenInfoServer::new_with_fallback(endpoint, query_parameter, None, parser)
    }

    pub fn new_with_fallback<P>(
        endpoint: &str,
        query_parameter: Option<&str>,
        fallback_endpoint: Option<&str>,
        parser: P,
    ) -> ::std::result::Result<TokenInfoServer, InitializationError>
    where
        P: TokenInfoParser,
    {
        let url_prefix = assemble_url_prefix(endpoint, &query_parameter).map_err(
            |err| {
                InitializationError(err)
            },
        )?;

        let fallback_url_prefix = if let Some(fallback_endpoint_address) = fallback_endpoint {
            Some(assemble_url_prefix(
                fallback_endpoint_address,
                &query_parameter,
            ).map_err(|err| InitializationError(err))?)
        } else {
            None
        };

        let client = Client::new().map_err(
            |err| InitializationError(err.to_string()),
        )?;
        Ok(TokenInfoServer {
            url_prefix: Arc::new(url_prefix),
            fallback_url_prefix: fallback_url_prefix.map(|fb| Arc::new(fb)),
            http_client: client,
            parser: Arc::new(parser),
        })
    }

    pub fn from_env<P>(parser: P) -> ::std::result::Result<TokenInfoServer, InitializationError>
    where
        P: TokenInfoParser,
    {
        let endpoint = env::var("TOKKIT_TOKEN_INFO_ENDPOINT").map_err(|err| {
            InitializationError(format!("'TOKKIT_TOKEN_INFO_ENDPOINT':{}", err))
        })?;
        let query_parameter = match env::var("TOKKIT_TOKEN_INFO_QUERY_PARAMETER") {
            Ok(v) => Some(v),
            Err(env::VarError::NotPresent) => None,
            Err(err) => {
                return Err(InitializationError(err.to_string())).map_err(|err| {
                    InitializationError(format!("'TOKKIT_TOKEN_INFO_QUERY_PARAMETER':{}", err))
                })
            }
        };
        let fallback_endpoint = match env::var("TOKKIT_TOKEN_INFO_FALLBACK_ENDPOINT") {
            Ok(v) => Some(v),
            Err(env::VarError::NotPresent) => None,
            Err(err) => {
                return Err(InitializationError(err.to_string())).map_err(|err| {
                    InitializationError(format!("'TOKKIT_TOKEN_INFO_FALLBACK_ENDPOINT':{}", err))
                })
            }
        };
        TokenInfoServer::new_with_fallback(
            &endpoint,
            query_parameter.as_ref().map(|x| &**x),
            fallback_endpoint.as_ref().map(|x| &**x),
            parser,
        )
    }
}

fn assemble_url_prefix(
    endpoint: &str,
    query_parameter: &Option<&str>,
) -> ::std::result::Result<String, String> {
    let mut url_prefix = String::new();
    if let &Some(query_parameter) = query_parameter {
        if url_prefix.ends_with('/') {
            url_prefix.pop();
        }
        url_prefix.push_str(&format!("?{}=", query_parameter));
    } else {
        if !url_prefix.ends_with('/') {
            url_prefix.push('/');
        }
    }
    let test_url = format!("{}test_token", url_prefix);
    let _ = test_url.parse::<Url>().map_err(
        |err| format!("Invalid URL: {}", err),
    )?;
    Ok(url_prefix)
}

impl TokenInfoService for TokenInfoServer {
    fn get_token_info(&self, token: &Token) -> Result<TokenInfo> {
        let url: Url = complete_url(&self.url_prefix, token)?;
        let fallback_url = match self.fallback_url_prefix {
            Some(ref fb_url_prefix) => Some(complete_url(fb_url_prefix, token)?),
            None => None,
        };
        get_with_fallback(token, url, fallback_url, &self.http_client, &*self.parser)
    }
}

impl Clone for TokenInfoServer {
    fn clone(&self) -> Self {
        TokenInfoServer {
            url_prefix: self.url_prefix.clone(),
            fallback_url_prefix: self.fallback_url_prefix.clone(),
            http_client: self.http_client.clone(),
            parser: self.parser.clone(),
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
    parser: &TokenInfoParser,
) -> Result<TokenInfo> {
    get_remote(token, url, client, parser).or_else(|err| match err {
        Error(ErrorKind::ClientError(_, _), _) => Err(err),
        _ => {
            fallback_url
                .map(|url| get_remote(token, url, client, parser))
                .unwrap_or(Err(err))
        }
    })
}

fn get_remote(
    token: &Token,
    url: Url,
    http_client: &Client,
    parser: &TokenInfoParser,
) -> Result<TokenInfo> {
    match http_client.get(url).send() {
        Ok(ref mut response) => process_response(response, parser),
        Err(err) => Err(ErrorKind::Connection(err.to_string()).into()),
    }
}

fn process_response(response: &mut Response, parser: &TokenInfoParser) -> Result<TokenInfo> {
    let mut body = Vec::new();
    response.read_to_end(&mut body)?;
    if *response.status() == StatusCode::Ok {
        let result: TokenInfo = match parser.parse(&body) {
            Ok(info) => info,
            Err(msg) => bail!(ErrorKind::InvalidResponseContent(msg)),
        };
        Ok(result)
    } else if *response.status() == StatusCode::Unauthorized {
        let msg = str::from_utf8(&body)?;
        bail!(ErrorKind::NotAuthenticated(
            format!("The server refused the token: {}", msg),
        ))
    } else if response.status().is_client_error() {
        let msg = str::from_utf8(&body)?;
        bail!(ErrorKind::ClientError(
            response.status().to_string(),
            msg.to_string(),
        ))
    } else if response.status().is_server_error() {
        let msg = str::from_utf8(&body)?;
        bail!(ErrorKind::ServerError(
            response.status().to_string(),
            msg.to_string(),
        ))
    } else {
        let msg = str::from_utf8(&body)?;
        bail!(format!(
            "Unexpected response({}): {}",
            response.status(),
            msg
        ))
    }

}

impl From<UrlError> for Error {
    fn from(what: UrlError) -> Self {
        ErrorKind::UrlError(what.to_string()).into()
    }
}

impl From<str::Utf8Error> for Error {
    fn from(what: str::Utf8Error) -> Self {
        ErrorKind::InvalidResponseContent(what.to_string()).into()
    }
}
