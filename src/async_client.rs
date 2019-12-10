use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::Executor;
use futures::*;
use hyper::client::connect::Connect;
use hyper::client::HttpConnector;
use hyper::{Body, Client, Response, StatusCode, Uri};
use hyper_tls::HttpsConnector;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::RetryIf;

use client::assemble_url_prefix;
use metrics::{DevNullMetricsCollector, MetricsCollector};
use parsers::*;
use {AccessToken, InitializationError, InitializationResult, TokenInfo};
use {TokenInfoError, TokenInfoErrorKind, TokenInfoResult};

pub type HttpClient = Client<HttpsConnector<HttpConnector>, Body>;

/// Gives a `TokenInfo` for an `AccessToken`.
///
/// See [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
pub trait AsyncTokenInfoService {
    /// Gives a `TokenInfo` for an `AccessToken`.
    fn introspect(
        &self,
        token: &AccessToken,
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError> + Send + 'static>;
    /// Gives a `TokenInfo` for an `AccessToken` with retries.
    ///
    /// `budget` defines the duration the retries may take
    /// until the whole call is considered a failure.
    fn introspect_with_retry(
        &self,
        token: &AccessToken,
        budget: Duration,
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError> + Send + 'static>;
}

/// Gives a `TokenInfo` for an `AccessToken`.
///
/// This is a "light" version that does not have its own HTTP client.
/// Instead it has to be passed on every call.
///
/// See [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
pub trait AsyncTokenInfoServiceLight {
    /// Gives a `TokenInfo` for an `AccessToken`.
    fn introspect<C>(
        &self,
        token: &AccessToken,
        http_client: &Client<C, Body>,
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError> + Send + 'static>
    where
        C: Connect + Send + 'static;
    /// Gives a `TokenInfo` for an `AccessToken` with retries.
    ///
    /// `budget` defines the duration the retries may take
    /// until the whole call is considered a failure.
    fn introspect_with_retry<C>(
        &self,
        token: &AccessToken,
        budget: Duration,
        http_client: &Client<C, Body>,
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError> + Send + 'static>
    where
        C: Connect + Send + 'static;
}

/// A complete introspection client that owns a
/// HTTP client.
///
/// This client can also be created from the factory methods in
/// `AsyncTokenInfoServiceClientLight`:
///
/// * `AsyncTokenInfoServiceClientLight::with_client`
/// * `AsyncTokenInfoServiceClientLight::with_default_client`
#[derive(Clone)]
pub struct AsyncTokenInfoServiceClient<P, M, C = HttpsConnector<HttpConnector>> {
    url_prefix: Arc<String>,
    fallback_url_prefix: Option<Arc<String>>,
    http_client: Client<C, Body>,
    parser: P,
    metrics_collector: M,
}

impl<P, M, C> AsyncTokenInfoServiceClient<P, M, C>
where
    P: TokenInfoParser + Clone + Send + 'static,
    M: MetricsCollector + Clone + Send + 'static,
    C: Connect + Send + 'static,
{
    pub fn new(
        http_client: Client<C, Body>,
        endpoint: &str,
        query_parameter: Option<&str>,
        fallback_endpoint: Option<&str>,
        parser: P,
    ) -> InitializationResult<AsyncTokenInfoServiceClient<P, DevNullMetricsCollector, C>> {
        AsyncTokenInfoServiceClient::with_metrics(
            http_client,
            endpoint,
            query_parameter,
            fallback_endpoint,
            parser,
            DevNullMetricsCollector,
        )
    }

    pub fn with_metrics(
        http_client: Client<C, Body>,
        endpoint: &str,
        query_parameter: Option<&str>,
        fallback_endpoint: Option<&str>,
        parser: P,
        metrics_collector: M,
    ) -> InitializationResult<AsyncTokenInfoServiceClient<P, M, C>> {
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

        Ok(AsyncTokenInfoServiceClient {
            url_prefix: Arc::new(url_prefix),
            fallback_url_prefix: fallback_url_prefix.map(|fb| Arc::new(fb)),
            parser: parser,
            metrics_collector: metrics_collector,
            http_client,
        })
    }

    fn create(
        http_client: Client<C, Body>,
        url_prefix: Arc<String>,
        fallback_url_prefix: Option<Arc<String>>,
        parser: P,
        metrics_collector: M,
    ) -> AsyncTokenInfoServiceClient<P, M, C> {
        AsyncTokenInfoServiceClient {
            url_prefix,
            fallback_url_prefix,
            parser,
            metrics_collector,
            http_client,
        }
    }
}

impl<P, M, C> AsyncTokenInfoService for AsyncTokenInfoServiceClient<P, M, C>
where
    P: TokenInfoParser + Clone + Send + 'static,
    M: MetricsCollector + Clone + Send + 'static,
    C: Connect + Send + 'static,
{
    fn introspect(
        &self,
        token: &AccessToken,
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError> + Send + 'static> {
        let start = Instant::now();
        self.metrics_collector.incoming_introspection_request();

        let metrics_collector = self.metrics_collector.clone();
        let f = execute_once(
            self.http_client.clone(),
            token.clone(),
            &self.url_prefix,
            self.parser.clone(),
            self.metrics_collector.clone(),
        )
        .then(move |result| {
            match result {
                Ok(_) => {
                    metrics_collector.introspection_request(start);
                    metrics_collector.introspection_request_success(start)
                }
                Err(_) => {
                    metrics_collector.introspection_request(start);
                    metrics_collector.introspection_request_failure(start)
                }
            }
            result
        });
        Box::new(f)
    }

    fn introspect_with_retry(
        &self,
        token: &AccessToken,
        budget: Duration,
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError> + Send + 'static> {
        let start = Instant::now();
        self.metrics_collector.incoming_introspection_request();

        let metrics_collector = self.metrics_collector.clone();
        let f = execute_with_retry(
            &self.http_client,
            token.clone(),
            &self.url_prefix,
            self.parser.clone(),
            budget,
            self.metrics_collector.clone(),
        )
        .then(move |result| {
            match result {
                Ok(_) => {
                    metrics_collector.introspection_request(start);
                    metrics_collector.introspection_request_success(start)
                }
                Err(_) => {
                    metrics_collector.introspection_request(start);
                    metrics_collector.introspection_request_failure(start)
                }
            }
            result
        });
        Box::new(f)
    }
}

/// A an introspection client that does not have its own HTTP Client
///
/// This client can also be used as a factory factory for
/// `AsyncTokenInfoServiceClient`:
///
/// * `AsyncTokenInfoServiceClientLight::with_client`
/// * `AsyncTokenInfoServiceClientLight::with_default_client`
#[derive(Clone)]
pub struct AsyncTokenInfoServiceClientLight<P, M> {
    url_prefix: Arc<String>,
    fallback_url_prefix: Option<Arc<String>>,
    parser: P,
    metrics_collector: M,
}

impl<P, M> AsyncTokenInfoServiceClientLight<P, M>
where
    P: TokenInfoParser + Clone + Send + 'static,
    M: MetricsCollector + Clone + Send + 'static,
{
    pub fn new(
        endpoint: &str,
        query_parameter: Option<&str>,
        fallback_endpoint: Option<&str>,
        parser: P,
    ) -> InitializationResult<AsyncTokenInfoServiceClientLight<P, DevNullMetricsCollector>> {
        AsyncTokenInfoServiceClientLight::with_metrics(
            endpoint,
            query_parameter,
            fallback_endpoint,
            parser,
            DevNullMetricsCollector,
        )
    }

    pub fn with_metrics(
        endpoint: &str,
        query_parameter: Option<&str>,
        fallback_endpoint: Option<&str>,
        parser: P,
        metrics_collector: M,
    ) -> InitializationResult<AsyncTokenInfoServiceClientLight<P, M>> {
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

        Ok(AsyncTokenInfoServiceClientLight {
            url_prefix: Arc::new(url_prefix),
            fallback_url_prefix: fallback_url_prefix.map(|fb| Arc::new(fb)),
            parser: parser,
            metrics_collector: metrics_collector,
        })
    }

    /// Creates an `AsyncTokenInfoService` with the given HttpClient
    pub fn with_client<C>(
        &self,
        http_client: Client<C, Body>,
    ) -> AsyncTokenInfoServiceClient<P, M, C>
    where
        C: Connect + Send + 'static,
    {
        AsyncTokenInfoServiceClient::create(
            http_client,
            self.url_prefix.clone(),
            self.fallback_url_prefix.clone(),
            self.parser.clone(),
            self.metrics_collector.clone(),
        )
    }

    /// Creates an `AsyncTokenInfoService` with a default client using
    /// the given number of threads to do DNS resolving
    pub fn with_default_client(
        &self,
        num_dns_threads: usize,
    ) -> InitializationResult<AsyncTokenInfoServiceClient<P, M, HttpsConnector<HttpConnector>>>
    {
        let http_client = default_http_client(num_dns_threads)?;

        Ok(self.with_client(http_client))
    }

    /// Creates an `AsyncTokenInfoService` with a default client using
    /// the given number of threads to do DNS resolving and using
    /// the given `Executor`
    pub fn with_default_client_and_executor<E>(
        &self,
        num_dns_threads: usize,
        executor: E,
    ) -> InitializationResult<AsyncTokenInfoServiceClient<P, M, HttpsConnector<HttpConnector>>>
    where
        E: Executor<Box<Future<Item = (), Error = ()> + Send + 'static>> + Send + Sync + 'static,
    {
        let http_client = default_http_client_with_executor(num_dns_threads, executor)?;

        Ok(self.with_client(http_client))
    }
}

/// Creates a default HTTPS client with the given number of threads for DNS resolving
pub fn default_http_client(num_dns_threads: usize) -> Result<HttpClient, InitializationError> {
    let https = HttpsConnector::new(num_dns_threads)?;
    let http_client = ::hyper::Client::builder()
        .http1_writev(false)
        .build::<_, Body>(https);
    Ok(http_client)
}

/// Creates a default HTTPS client with the given number of
/// threads for DNS resolving using the given `Executor`
pub fn default_http_client_with_executor<E>(
    num_dns_threads: usize,
    executor: E,
) -> Result<HttpClient, InitializationError>
where
    E: Executor<Box<Future<Item = (), Error = ()> + Send + 'static>> + Send + Sync + 'static,
{
    let https = HttpsConnector::new(num_dns_threads)?;
    let http_client = ::hyper::Client::builder()
        .http1_writev(false)
        .executor(executor)
        .build::<_, Body>(https);
    Ok(http_client)
}

impl<P, M> AsyncTokenInfoServiceLight for AsyncTokenInfoServiceClientLight<P, M>
where
    P: TokenInfoParser + Clone + Send + 'static,
    M: MetricsCollector + Clone + Send + 'static,
{
    fn introspect<C>(
        &self,
        token: &AccessToken,
        http_client: &Client<C>,
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError> + Send + 'static>
    where
        C: Connect + Send + 'static,
    {
        let start = Instant::now();
        self.metrics_collector.incoming_introspection_request();

        let metrics_collector = self.metrics_collector.clone();
        let f = execute_once(
            http_client.clone(),
            token.clone(),
            &self.url_prefix,
            self.parser.clone(),
            self.metrics_collector.clone(),
        )
        .then(move |result| {
            match result {
                Ok(_) => {
                    metrics_collector.introspection_request(start);
                    metrics_collector.introspection_request_success(start)
                }
                Err(_) => {
                    metrics_collector.introspection_request(start);
                    metrics_collector.introspection_request_failure(start)
                }
            }
            result
        });
        Box::new(f)
    }

    fn introspect_with_retry<C>(
        &self,
        token: &AccessToken,
        budget: Duration,
        http_client: &Client<C>,
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError> + Send + 'static>
    where
        C: Connect + Send + 'static,
    {
        let start = Instant::now();
        self.metrics_collector.incoming_introspection_request();

        let metrics_collector = self.metrics_collector.clone();
        let f = execute_with_retry(
            http_client,
            token.clone(),
            &self.url_prefix,
            self.parser.clone(),
            budget,
            self.metrics_collector.clone(),
        )
        .then(move |result| {
            match result {
                Ok(_) => {
                    metrics_collector.introspection_request(start);
                    metrics_collector.introspection_request_success(start)
                }
                Err(_) => {
                    metrics_collector.introspection_request(start);
                    metrics_collector.introspection_request_failure(start)
                }
            }
            result
        });
        Box::new(f)
    }
}

fn process_response<P>(
    response: Response<Body>,
    parser: P,
) -> Box<Future<Item = TokenInfo, Error = TokenInfoError> + Send + 'static>
where
    P: TokenInfoParser + Clone + Send + 'static,
{
    let status = response.status();
    let f = response
        .into_body()
        .map_err(|err| TokenInfoErrorKind::Io(format!("Could not get body chunks: {}", err)))
        .concat2()
        .and_then(move |body| {
            if status == StatusCode::OK {
                let result = match parser.parse(&body) {
                    Ok(info) => Ok(info),
                    Err(err) => {
                        let msg: String = String::from_utf8_lossy(&body).into();
                        Err(TokenInfoErrorKind::InvalidResponseContent(format!(
                            "{}: {}",
                            err, msg
                        )))
                    }
                };
                result
            } else if status == StatusCode::UNAUTHORIZED {
                let msg = String::from_utf8_lossy(&body);
                Err(TokenInfoErrorKind::NotAuthenticated(format!(
                    "The server refused the token: {}",
                    msg
                )))
            } else if status.is_client_error() {
                let msg = String::from_utf8_lossy(&body).into();
                Err(TokenInfoErrorKind::Client(msg))
            } else if status.is_server_error() {
                let msg = String::from_utf8_lossy(&body).into();
                Err(TokenInfoErrorKind::Server(msg))
            } else {
                let msg = String::from_utf8_lossy(&body).into();
                Err(TokenInfoErrorKind::Other(msg))
            }
        })
        .map_err(Into::into);

    Box::new(f)
}

fn execute_with_retry<M, P, C>(
    http_client: &Client<C, Body>,
    token: AccessToken,
    url_prefix: &str,
    parser: P,
    budget: Duration,
    metrics_collector: M,
) -> Box<Future<Item = TokenInfo, Error = TokenInfoError> + Send + 'static>
where
    P: TokenInfoParser + Clone + Send + 'static,
    M: MetricsCollector + Clone + Send + 'static,
    C: Connect + Send + 'static,
{
    if budget == Duration::from_secs(0) {
        return Box::new(future::err(
            TokenInfoErrorKind::Other("Initial reuest budget was 0".into()).into(),
        ));
    }

    let deadline = Instant::now() + budget;
    let token = token.clone();
    let http_client = http_client.clone();
    let metrics_collector = metrics_collector.clone();

    let url_prefix = url_prefix.to_string();
    let parser = parser.clone();

    let retry_strategy = ExponentialBackoff::from_millis(10).map(jitter);

    let action = move || {
        if Instant::now() <= deadline {
            execute_once(
                http_client.clone(),
                token.clone(),
                &url_prefix.clone(),
                parser.clone(),
                metrics_collector.clone(),
            )
        } else {
            Box::new(future::err(TokenInfoErrorKind::BudgetExceeded.into()))
        }
    };

    let mut n = 1;
    let condition = move |err: &TokenInfoError| {
        warn!(
            "Retry({}) on token introspection service. Reason: {}",
            n, err
        );
        n += 1;
        Instant::now() <= deadline && err.is_retry_suggested()
    };

    let future =
        RetryIf::spawn(retry_strategy, action, condition).map_err(|retry_err| match retry_err {
            ::tokio_retry::Error::OperationError(op_err) => op_err,
            ::tokio_retry::Error::TimerError(err) => {
                TokenInfoErrorKind::Io(format!("Retry Timer Error: {} ", err)).into()
            }
        });

    Box::new(future)
}

fn execute_once<P, M, C>(
    client: Client<C, Body>,
    token: AccessToken,
    url_prefix: &str,
    parser: P,
    metrics_collector: M,
) -> Box<Future<Item = TokenInfo, Error = TokenInfoError> + Send + 'static>
where
    P: TokenInfoParser + Clone + Send + 'static,
    M: MetricsCollector + Send + 'static,
    C: Connect + Send + 'static,
{
    let start = Instant::now();
    let f = future::result(complete_url(url_prefix, &token))
        .and_then(move |uri| client.get(uri).map_err(Into::into))
        .then(move |result| {
            match result {
                Ok(_) => {
                    metrics_collector.introspection_service_call(start);
                    metrics_collector.introspection_service_call_success(start)
                }
                Err(_) => {
                    metrics_collector.introspection_service_call(start);
                    metrics_collector.introspection_service_call_failure(start)
                }
            }
            result
        })
        .and_then(|response| process_response(response, parser));
    Box::new(f)
}

fn complete_url(url_prefix: &str, token: &AccessToken) -> TokenInfoResult<Uri> {
    let mut url_str = url_prefix.to_string();
    url_str.push_str(token.0.as_ref());
    let url = url_str.parse()?;
    Ok(url)
}

impl From<::hyper_tls::Error> for InitializationError {
    fn from(err: ::hyper_tls::Error) -> Self {
        InitializationError(format!("Could not initialize hyper_tls: {}", err))
    }
}

impl From<::hyper::error::Error> for TokenInfoError {
    fn from(err: ::hyper::error::Error) -> Self {
        TokenInfoErrorKind::Other(err.to_string()).into()
    }
}

impl From<hyper::http::uri::InvalidUri> for TokenInfoError {
    fn from(err: hyper::http::uri::InvalidUri) -> Self {
        TokenInfoErrorKind::UrlError(err.to_string()).into()
    }
}
