use std::sync::Arc;
use std::io::Read;
use std::env;
use std::str;
use reqwest::{Url, Client, StatusCode, UrlError, Response};
use token_info::*;
use token_info::error::Error;

/// A builder for a `RemoteTokenInfoService`
pub struct RemoteTokenInfoServiceBuilder<P: TokenInfoParser> {
    pub parser: Option<P>,
    pub endpoint: Option<String>,
    pub query_parameter: Option<String>,
    pub fallback_endpoint: Option<String>,
}

impl<P: TokenInfoParser> RemoteTokenInfoServiceBuilder<P> {
    /// Create a new `RemoteTokenInfoServiceBuilder` with the given `TokenInfoParser`
    /// already set.
    pub fn new(parser: P) -> Self {
        let mut builder = Self::default();
        builder.with_parser(parser);
        builder
    }

    /// Sets the `TokenInfoParser`. The `TokenInfoParser` is mandatory.
    pub fn with_parser(&mut self, parser: P) -> &mut Self {
        self.parser = Some(parser);
        self
    }

    /// Sets the introspection endpoint. The introspection endpoint is mandatory.
    pub fn with_endpoint<T: Into<String>>(&mut self, endpoint: T) -> &mut Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Sets a fallback for the introspection endpoint. The fallback is optional.
    pub fn with_fallback_endpoint<T: Into<String>>(&mut self, endpoint: T) -> &mut Self {
        self.fallback_endpoint = Some(endpoint.into());
        self
    }

    /// Sets the query parameter for the access token.
    /// If ommitted the access token will be part of the URL.
    pub fn with_query_parameter<T: Into<String>>(&mut self, parameter: T) -> &mut Self {
        self.query_parameter = Some(parameter.into());
        self
    }

    /// Build the `RemoteTokenInfoService`. Fails if not all mandatory fields are set.
    pub fn build(self) -> InitializationResult<RemoteTokenInfoService> {
        let parser = if let Some(parser) = self.parser {
            parser
        } else {
            return Err(InitializationError("No token info parser.".into()));
        };

        let endpoint = if let Some(endpoint) = self.endpoint {
            endpoint
        } else {
            return Err(InitializationError("No endpoint.".into()));
        };

        RemoteTokenInfoService::new::<P>(
            &endpoint,
            self.query_parameter.as_ref().map(|s| &**s),
            self.fallback_endpoint.as_ref().map(|s| &**s),
            parser,
        )
    }

    /// Creates a new `RemoteTokenInfoServiceBuilder` from environment parameters.
    ///
    /// The following variables used to identify the field in a token info response:
    ///
    /// * `TOKKIT_TOKEN_INTROSPECTION_ENDPOINT`(mandatory): The endpoint of the service
    /// * `TOKKIT_TOKEN_INTROSPECTION_QUERY_PARAMETER`(optional): The request parameter
    /// * `TOKKIT_TOKEN_INTROSPECTION_FALLBACK_ENDPOINT`(optional): A fallback endpoint
    ///
    /// If `TOKKIT_TOKEN_INTROSPECTION_QUERY_PARAMETER` is ommitted the access token
    /// will be part of the URL.
    pub fn from_env() -> InitializationResult<Self> {
        let endpoint = env::var("TOKKIT_TOKEN_INTROSPECTION_ENDPOINT").map_err(
            |err| {
                InitializationError(format!("'TOKKIT_TOKEN_INTROSPECTION_ENDPOINT': {}", err))
            },
        )?;
        let query_parameter = match env::var("TOKKIT_TOKEN_INTROSPECTION_QUERY_PARAMETER") {
            Ok(v) => Some(v),
            Err(env::VarError::NotPresent) => None,
            Err(err) => {
                return Err(InitializationError(format!(
                    "'TOKKIT_TOKEN_INTROSPECTION_QUERY_PARAMETER': {}",
                    err
                )))
            }
        };
        let fallback_endpoint = match env::var("TOKKIT_TOKEN_INTROSPECTION_FALLBACK_ENDPOINT") {
            Ok(v) => Some(v),
            Err(env::VarError::NotPresent) => None,
            Err(err) => {
                return Err(InitializationError(format!(
                    "'TOKKIT_TOKEN_INTROSPECTION_FALLBACK_ENDPOINT': {}",
                    err
                )))
            }
        };
        Ok(RemoteTokenInfoServiceBuilder {
            parser: Default::default(),
            endpoint: Some(endpoint),
            query_parameter: query_parameter,
            fallback_endpoint: fallback_endpoint,
        })
    }
}

impl RemoteTokenInfoServiceBuilder<parsers::PlanBTokenInfoParser> {
    /// Create a new `RemoteTokenInfoService` with prepared settings.
    ///
    /// [More information](http://planb.readthedocs.io/en/latest/intro.html#token-info)
    pub fn plan_b(
        endpoint: String,
    ) -> RemoteTokenInfoServiceBuilder<parsers::PlanBTokenInfoParser> {
        let mut builder = Self::default();
        builder.with_parser(parsers::PlanBTokenInfoParser);
        builder.with_endpoint(endpoint);
        builder.with_query_parameter("access_token");
        builder
    }

    /// Create a new `RemoteTokenInfoService` with prepared settings from environment variables.
    ///
    /// `TOKKIT_TOKEN_INTROSPECTION_ENDPOINT` and
    /// `TOKKIT_TOKEN_INTROSPECTION_FALLBACK_ENDPOINT` will be used and
    /// `TOKKIT_TOKEN_INTROSPECTION_QUERY_PARAMETER` will have no effect.
    ///
    /// [More information](http://planb.readthedocs.io/en/latest/intro.html#token-info)
    pub fn plan_b_from_env()
        -> InitializationResult<RemoteTokenInfoServiceBuilder<parsers::PlanBTokenInfoParser>>
    {
        let mut builder = Self::from_env()?;
        builder.with_parser(parsers::PlanBTokenInfoParser);
        builder.with_query_parameter("access_token");
        Ok(builder)
    }
}

impl RemoteTokenInfoServiceBuilder<parsers::GoogleV3TokenInfoParser> {
    /// Create a new `RemoteTokenInfoService` with prepared settings.
    ///
    /// [More information](https://developers.google.
    /// com/identity/protocols/OAuth2UserAgent#validatetoken)
    pub fn google_v3() -> RemoteTokenInfoServiceBuilder<parsers::GoogleV3TokenInfoParser> {
        let mut builder = Self::default();
        builder.with_parser(parsers::GoogleV3TokenInfoParser);
        builder.with_endpoint("https://www.googleapis.com/oauth2/v3/tokeninfo");
        builder.with_query_parameter("access_token");
        builder
    }
}

impl RemoteTokenInfoServiceBuilder<parsers::AmazonTokenInfoParser> {
    /// Create a new `RemoteTokenInfoService` with prepared settings.
    ///
    /// [More information](https://images-na.ssl-images-amazon.
    /// com/images/G/01/lwa/dev/docs/website-developer-guide._TTH_.pdf)
    pub fn amazon() -> RemoteTokenInfoServiceBuilder<parsers::AmazonTokenInfoParser> {
        let mut builder = Self::default();
        builder.with_parser(parsers::AmazonTokenInfoParser);
        builder.with_endpoint("https://api.amazon.com/auth/O2/tokeninfo");
        builder.with_query_parameter("access_token");
        builder
    }
}


impl<P: TokenInfoParser> Default for RemoteTokenInfoServiceBuilder<P> {
    fn default() -> Self {
        RemoteTokenInfoServiceBuilder {
            parser: Default::default(),
            endpoint: Default::default(),
            query_parameter: Default::default(),
            fallback_endpoint: Default::default(),
        }
    }
}

/// Introspects an `AccessToken` remotely.
///
/// Returns the result as a `TokenInfo`.
///
/// The `RemoteTokenInfoService` will not do any retries on failures except possibly calling a
/// fallback.
pub struct RemoteTokenInfoService {
    url_prefix: Arc<String>,
    fallback_url_prefix: Option<Arc<String>>,
    http_client: Client,
    parser: Arc<TokenInfoParser>,
}

impl RemoteTokenInfoService {
    /// Creates a new `RemoteTokenInfoService`. Fails if one of the given endpoints is invalid.
    pub fn new<P>(
        endpoint: &str,
        query_parameter: Option<&str>,
        fallback_endpoint: Option<&str>,
        parser: P,
    ) -> InitializationResult<RemoteTokenInfoService>
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
        Ok(RemoteTokenInfoService {
            url_prefix: Arc::new(url_prefix),
            fallback_url_prefix: fallback_url_prefix.map(|fb| Arc::new(fb)),
            http_client: client,
            parser: Arc::new(parser),
        })
    }
}

fn assemble_url_prefix(
    endpoint: &str,
    query_parameter: &Option<&str>,
) -> ::std::result::Result<String, String> {
    let mut url_prefix = String::from(endpoint);
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

impl TokenInfoService for RemoteTokenInfoService {
    fn introspect(&self, token: &AccessToken) -> Result<TokenInfo> {
        let url: Url = complete_url(&self.url_prefix, token)?;
        let fallback_url = match self.fallback_url_prefix {
            Some(ref fb_url_prefix) => Some(complete_url(fb_url_prefix, token)?),
            None => None,
        };
        get_with_fallback(url, fallback_url, &self.http_client, &*self.parser)
    }
}

impl Clone for RemoteTokenInfoService {
    fn clone(&self) -> Self {
        RemoteTokenInfoService {
            url_prefix: self.url_prefix.clone(),
            fallback_url_prefix: self.fallback_url_prefix.clone(),
            http_client: self.http_client.clone(),
            parser: self.parser.clone(),
        }
    }
}

fn complete_url(url_prefix: &str, token: &AccessToken) -> Result<Url> {
    let mut url_str = url_prefix.to_string();
    url_str.push_str(token.0.as_ref());
    let url = url_str.parse()?;
    Ok(url)
}

fn get_with_fallback(
    url: Url,
    fallback_url: Option<Url>,
    client: &Client,
    parser: &TokenInfoParser,
) -> Result<TokenInfo> {
    get_remote(url, client, parser).or_else(|err| match err {
        Error(ErrorKind::ClientError(_, _), _) => Err(err),
        _ => {
            fallback_url
                .map(|url| get_remote(url, client, parser))
                .unwrap_or(Err(err))
        }
    })
}

fn get_remote(url: Url, http_client: &Client, parser: &TokenInfoParser) -> Result<TokenInfo> {
    let mut request_builder = http_client.get(url).map_err(
        |err| ErrorKind::Other(err.to_string()),
    )?;
    match request_builder.send() {
        Ok(ref mut response) => process_response(response, parser),
        Err(err) => Err(ErrorKind::Connection(err.to_string()).into()),
    }
}

fn process_response(response: &mut Response, parser: &TokenInfoParser) -> Result<TokenInfo> {
    let mut body = Vec::new();
    response.read_to_end(&mut body)?;
    if response.status() == StatusCode::Ok {
        let result: TokenInfo = match parser.parse(&body) {
            Ok(info) => info,
            Err(msg) => bail!(ErrorKind::InvalidResponseContent(msg)),
        };
        Ok(result)
    } else if response.status() == StatusCode::Unauthorized {
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
