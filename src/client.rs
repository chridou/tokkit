//! Different implementations

use std::sync::Arc;
use std::io::Read;
use std::env;
use std::str;
use std::time::Duration;

use reqwest::{Client, Response, StatusCode, Url, UrlError};
use failure::ResultExt;
use backoff::{Error as BackoffError, ExponentialBackoff, Operation};

use {AccessToken, InitializationError, InitializationResult, TokenInfo};
use parsers::*;
use {TokenInfoError, TokenInfoErrorKind, TokenInfoResult, TokenInfoService};
use metrics::{DevNullMetricsCollector, MetricsCollector};

#[cfg(feature = "async")]
use tokio_core::reactor::Handle;
#[cfg(feature = "async")]
use async_client::AsyncTokenInfoServiceClient;

/// A builder for a `TokenInfoServiceClient`
pub struct TokenInfoServiceClientBuilder<P: TokenInfoParser> {
    pub parser: Option<P>,
    pub endpoint: Option<String>,
    pub query_parameter: Option<String>,
    pub fallback_endpoint: Option<String>,
}

impl<P> TokenInfoServiceClientBuilder<P>
where
    P: TokenInfoParser + Sync + Send + 'static,
{
    /// Create a new `TokenInfoServiceClientBuilder` with the given `TokenInfoParser`
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

    /// Sets the introspection endpoint. The introspection endpoint is
    /// mandatory.
    pub fn with_endpoint<T: Into<String>>(&mut self, endpoint: T) -> &mut Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Sets a fallback for the introspection endpoint. The fallback is
    /// optional.
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

    /// Build the `TokenInfoServiceClient`. Fails if not all mandatory fields
    /// are set.
    pub fn build(self) -> InitializationResult<TokenInfoServiceClient> {
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

        TokenInfoServiceClient::new::<P>(
            &endpoint,
            self.query_parameter.as_ref().map(|s| &**s),
            self.fallback_endpoint.as_ref().map(|s| &**s),
            parser,
        )
    }

    /// Build the `TokenInfoServiceClient`. Fails if not all mandatory fields
    /// are set.
    #[cfg(feature = "async")]
    pub fn build_async(self, handle: &Handle) -> InitializationResult<AsyncTokenInfoServiceClient> {
        self.build_async_with_metrics(handle, DevNullMetricsCollector)
    }

    /// Build the `TokenInfoServiceClient`. Fails if not all mandatory fields
    /// are set.
    #[cfg(feature = "async")]
    pub fn build_async_with_metrics<M>(
        self,
        handle: &Handle,
        metrics_collector: M,
    ) -> InitializationResult<AsyncTokenInfoServiceClient>
    where
        M: MetricsCollector + 'static,
    {
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

        AsyncTokenInfoServiceClient::with_metrics::<P, M>(
            &endpoint,
            self.query_parameter.as_ref().map(|s| &**s),
            self.fallback_endpoint.as_ref().map(|s| &**s),
            parser,
            handle,
            metrics_collector,
        )
    }

    /// Creates a new `TokenInfoServiceClientBuilder` from environment parameters.
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
        let endpoint = env::var("TOKKIT_TOKEN_INTROSPECTION_ENDPOINT").map_err(|err| {
            InitializationError(format!("'TOKKIT_TOKEN_INTROSPECTION_ENDPOINT': {}", err))
        })?;
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
        Ok(TokenInfoServiceClientBuilder {
            parser: Default::default(),
            endpoint: Some(endpoint),
            query_parameter: query_parameter,
            fallback_endpoint: fallback_endpoint,
        })
    }
}

impl TokenInfoServiceClientBuilder<PlanBTokenInfoParser> {
    /// Create a new `TokenInfoServiceClient` with prepared settings.
    ///
    /// [More information](http://planb.readthedocs.io/en/latest/intro.html#token-info)
    pub fn plan_b(endpoint: String) -> TokenInfoServiceClientBuilder<PlanBTokenInfoParser> {
        let mut builder = Self::default();
        builder.with_parser(PlanBTokenInfoParser);
        builder.with_endpoint(endpoint);
        builder.with_query_parameter("access_token");
        builder
    }

    /// Create a new `TokenInfoServiceClient` with prepared settings from environment variables.
    ///
    /// `TOKKIT_TOKEN_INTROSPECTION_ENDPOINT` and
    /// `TOKKIT_TOKEN_INTROSPECTION_FALLBACK_ENDPOINT` will be used and
    /// `TOKKIT_TOKEN_INTROSPECTION_QUERY_PARAMETER` will have no effect.
    ///
    /// [More information](http://planb.readthedocs.io/en/latest/intro.html#token-info)
    pub fn plan_b_from_env(
) -> InitializationResult<TokenInfoServiceClientBuilder<PlanBTokenInfoParser>> {
        let mut builder = Self::from_env()?;
        builder.with_parser(PlanBTokenInfoParser);
        builder.with_query_parameter("access_token");
        Ok(builder)
    }
}

impl TokenInfoServiceClientBuilder<GoogleV3TokenInfoParser> {
    /// Create a new `TokenInfoServiceClient` with prepared settings.
    ///
    /// [More information](https://developers.google.
    /// com/identity/protocols/OAuth2UserAgent#validatetoken)
    pub fn google_v3() -> TokenInfoServiceClientBuilder<GoogleV3TokenInfoParser> {
        let mut builder = Self::default();
        builder.with_parser(GoogleV3TokenInfoParser);
        builder.with_endpoint("https://www.googleapis.com/oauth2/v3/tokeninfo");
        builder.with_query_parameter("access_token");
        builder
    }
}

impl TokenInfoServiceClientBuilder<AmazonTokenInfoParser> {
    /// Create a new `TokenInfoServiceClient` with prepared settings.
    ///
    /// [More information](https://images-na.ssl-images-amazon.
    /// com/images/G/01/lwa/dev/docs/website-developer-guide._TTH_.pdf)
    pub fn amazon() -> TokenInfoServiceClientBuilder<AmazonTokenInfoParser> {
        let mut builder = Self::default();
        builder.with_parser(AmazonTokenInfoParser);
        builder.with_endpoint("https://api.amazon.com/auth/O2/tokeninfo");
        builder.with_query_parameter("access_token");
        builder
    }
}

impl<P: TokenInfoParser> Default for TokenInfoServiceClientBuilder<P> {
    fn default() -> Self {
        TokenInfoServiceClientBuilder {
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
/// The `TokenInfoServiceClient` will do retries on failures and if possible call a
/// fallback.
pub struct TokenInfoServiceClient {
    url_prefix: Arc<String>,
    fallback_url_prefix: Option<Arc<String>>,
    http_client: Client,
    parser: Arc<TokenInfoParser + Sync + Send + 'static>,
}

impl TokenInfoServiceClient {
    /// Creates a new `TokenInfoServiceClient`. Fails if one of the given
    /// endpoints is invalid.
    pub fn new<P>(
        endpoint: &str,
        query_parameter: Option<&str>,
        fallback_endpoint: Option<&str>,
        parser: P,
    ) -> InitializationResult<TokenInfoServiceClient>
    where
        P: TokenInfoParser + Sync + Send + 'static,
    {
        let url_prefix = assemble_url_prefix(endpoint, &query_parameter)
            .map_err(|err| InitializationError(err))?;

        let fallback_url_prefix = if let Some(fallback_endpoint_address) = fallback_endpoint {
            Some(
                assemble_url_prefix(fallback_endpoint_address, &query_parameter)
                    .map_err(|err| InitializationError(err))?,
            )
        } else {
            None
        };

        let client = Client::new();
        Ok(TokenInfoServiceClient {
            url_prefix: Arc::new(url_prefix),
            fallback_url_prefix: fallback_url_prefix.map(|fb| Arc::new(fb)),
            http_client: client,
            parser: Arc::new(parser),
        })
    }
}

pub(crate) fn assemble_url_prefix(
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
    let _ = test_url
        .parse::<Url>()
        .map_err(|err| format!("Invalid URL: {}", err))?;
    Ok(url_prefix)
}

impl TokenInfoService for TokenInfoServiceClient {
    fn introspect(&self, token: &AccessToken) -> TokenInfoResult<TokenInfo> {
        let url: Url = complete_url(&self.url_prefix, token)?;
        let fallback_url = match self.fallback_url_prefix {
            Some(ref fb_url_prefix) => Some(complete_url(fb_url_prefix, token)?),
            None => None,
        };
        get_with_fallback(url, fallback_url, &self.http_client, &*self.parser)
    }
}

impl Clone for TokenInfoServiceClient {
    fn clone(&self) -> Self {
        TokenInfoServiceClient {
            url_prefix: self.url_prefix.clone(),
            fallback_url_prefix: self.fallback_url_prefix.clone(),
            http_client: self.http_client.clone(),
            parser: self.parser.clone(),
        }
    }
}

fn complete_url(url_prefix: &str, token: &AccessToken) -> TokenInfoResult<Url> {
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
) -> TokenInfoResult<TokenInfo> {
    get_from_remote(url, client, parser).or_else(|err| match *err.kind() {
        TokenInfoErrorKind::Client(_) => Err(err),
        _ => fallback_url
            .map(|url| get_from_remote(url, client, parser))
            .unwrap_or(Err(err)),
    })
}

fn get_from_remote(
    url: Url,
    http_client: &Client,
    parser: &TokenInfoParser,
) -> TokenInfoResult<TokenInfo> {
    let mut op = || match get_from_remote_no_retry(url.clone(), http_client, parser) {
        Ok(token_info) => Ok(token_info),
        Err(err) => match *err.kind() {
            TokenInfoErrorKind::InvalidResponseContent(_) => Err(BackoffError::Permanent(err)),
            TokenInfoErrorKind::UrlError(_) => Err(BackoffError::Permanent(err)),
            TokenInfoErrorKind::NotAuthenticated(_) => Err(BackoffError::Permanent(err)),
            TokenInfoErrorKind::Client(_) => Err(BackoffError::Permanent(err)),
            _ => Err(BackoffError::Transient(err)),
        },
    };

    let mut backoff = ExponentialBackoff::default();
    backoff.max_elapsed_time = Some(Duration::from_millis(200));
    backoff.initial_interval = Duration::from_millis(10);
    backoff.multiplier = 1.5;

    let notify = |err, _| {
        warn!("Retry on token info service: {}", err);
    };

    let retry_result = op.retry_notify(&mut backoff, notify);

    match retry_result {
        Ok(token_info) => Ok(token_info),
        Err(BackoffError::Transient(err)) => Err(err),
        Err(BackoffError::Permanent(err)) => Err(err),
    }
}

fn get_from_remote_no_retry(
    url: Url,
    http_client: &Client,
    parser: &TokenInfoParser,
) -> TokenInfoResult<TokenInfo> {
    let mut request_builder = http_client.get(url);
    match request_builder.send() {
        Ok(ref mut response) => process_response(response, parser),
        Err(err) => Err(TokenInfoErrorKind::Connection(err.to_string()).into()),
    }
}

fn process_response(
    response: &mut Response,
    parser: &TokenInfoParser,
) -> TokenInfoResult<TokenInfo> {
    let mut body = Vec::new();
    response
        .read_to_end(&mut body)
        .context(TokenInfoErrorKind::Io(
            "Could not read response bode".to_string(),
        ))?;
    if response.status() == StatusCode::Ok {
        let result: TokenInfo = match parser.parse(&body) {
            Ok(info) => info,
            Err(msg) => {
                return Err(TokenInfoErrorKind::InvalidResponseContent(msg.to_string()).into())
            }
        };
        Ok(result)
    } else if response.status() == StatusCode::Unauthorized {
        let msg = str::from_utf8(&body)?;
        return Err(TokenInfoErrorKind::NotAuthenticated(format!(
            "The server refused the token: {}",
            msg
        )).into());
    } else if response.status().is_client_error() {
        let msg = str::from_utf8(&body)?;
        return Err(TokenInfoErrorKind::Client(msg.to_string()).into());
    } else if response.status().is_server_error() {
        let msg = str::from_utf8(&body)?;
        return Err(TokenInfoErrorKind::Server(msg.to_string()).into());
    } else {
        let msg = str::from_utf8(&body)?;
        return Err(TokenInfoErrorKind::Other(msg.to_string()).into());
    }
}

impl From<UrlError> for TokenInfoError {
    fn from(what: UrlError) -> Self {
        TokenInfoErrorKind::UrlError(what.to_string()).into()
    }
}

impl From<str::Utf8Error> for TokenInfoError {
    fn from(what: str::Utf8Error) -> Self {
        TokenInfoErrorKind::InvalidResponseContent(what.to_string()).into()
    }
}
