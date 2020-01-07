use std::sync::Arc;
use std::time::{Duration, Instant};

use backoff_futures::BackoffExt;
use futures::*;
use futures::future::{self, BoxFuture};
use reqwest::{Client, Response, StatusCode, Url};

use crate::client::assemble_url_prefix;
use crate::metrics::{DevNullMetricsCollector, MetricsCollector};
use crate::parsers::*;
use crate::{AccessToken, InitializationError, InitializationResult, TokenInfo};
use crate::{TokenInfoError, TokenInfoErrorKind, TokenInfoResult};

pub type HttpClient = Client;

/// Gives a `TokenInfo` for an `AccessToken`.
///
/// See [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
pub trait AsyncTokenInfoService {
    /// Gives a `TokenInfo` for an `AccessToken`.
    fn introspect<'a>(
        &'a self,
        token: &'a AccessToken,
    ) -> BoxFuture<'a, Result<TokenInfo, TokenInfoError>>;
    /// Gives a `TokenInfo` for an `AccessToken` with retries.
    ///
    /// `budget` defines the duration the retries may take
    /// until the whole call is considered a failure.
    fn introspect_with_retry<'a>(
        &'a self,
        token: &'a AccessToken,
        budget: Duration,
    ) -> BoxFuture<'a, Result<TokenInfo, TokenInfoError>>;
}

/// Gives a `TokenInfo` for an `AccessToken`.
///
/// This is a "light" version that does not have its own HTTP client.
/// Instead it has to be passed on every call.
///
/// See [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
pub trait AsyncTokenInfoServiceLight {
    /// Gives a `TokenInfo` for an `AccessToken`.
    fn introspect<'a>(
        &'a self,
        token: &'a AccessToken,
        http_client: &'a Client,
    ) -> BoxFuture<'a, Result<TokenInfo, TokenInfoError>>;
    /// Gives a `TokenInfo` for an `AccessToken` with retries.
    ///
    /// `budget` defines the duration the retries may take
    /// until the whole call is considered a failure.
    fn introspect_with_retry<'a>(
        &'a self,
        token: &'a AccessToken,
        budget: Duration,
        http_client: &'a Client,
    ) -> BoxFuture<'a, Result<TokenInfo, TokenInfoError>>;
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
pub struct AsyncTokenInfoServiceClient<P, M> {
    url_prefix: Arc<String>,
    fallback_url_prefix: Option<Arc<String>>,
    http_client: Client,
    parser: P,
    metrics_collector: M,
}

impl<P> AsyncTokenInfoServiceClient<P, DevNullMetricsCollector>
where
    P: TokenInfoParser + Send,
{
    pub fn new(
        http_client: Client,
        endpoint: &str,
        query_parameter: Option<&str>,
        fallback_endpoint: Option<&str>,
        parser: P,
    ) -> InitializationResult<AsyncTokenInfoServiceClient<P, DevNullMetricsCollector>> {
        AsyncTokenInfoServiceClient::with_metrics(
            http_client,
            endpoint,
            query_parameter,
            fallback_endpoint,
            parser,
            DevNullMetricsCollector,
        )
    }
}

impl<P, M> AsyncTokenInfoServiceClient<P, M>
where
    P: TokenInfoParser + Send,
    M: MetricsCollector + Send,
{
    pub fn with_metrics(
        http_client: Client,
        endpoint: &str,
        query_parameter: Option<&str>,
        fallback_endpoint: Option<&str>,
        parser: P,
        metrics_collector: M,
    ) -> InitializationResult<AsyncTokenInfoServiceClient<P, M>> {
        let url_prefix = assemble_url_prefix(endpoint, &query_parameter)
            .map_err(InitializationError)?;

        let fallback_url_prefix = if let Some(fallback_endpoint_address) = fallback_endpoint {
            Some(
                assemble_url_prefix(fallback_endpoint_address, &query_parameter)
                    .map_err(InitializationError)?,
            )
        } else {
            None
        };

        Ok(AsyncTokenInfoServiceClient {
            url_prefix: Arc::new(url_prefix),
            fallback_url_prefix: fallback_url_prefix.map(Arc::new),
            parser,
            metrics_collector,
            http_client,
        })
    }

    fn create(
        http_client: Client,
        url_prefix: Arc<String>,
        fallback_url_prefix: Option<Arc<String>>,
        parser: P,
        metrics_collector: M,
    ) -> AsyncTokenInfoServiceClient<P, M> {
        AsyncTokenInfoServiceClient {
            url_prefix,
            fallback_url_prefix,
            parser,
            metrics_collector,
            http_client,
        }
    }
}

impl<P, M> AsyncTokenInfoService for AsyncTokenInfoServiceClient<P, M>
where
    P: TokenInfoParser + Send + Sync,
    M: MetricsCollector + Send + Sync,
{
    fn introspect<'a>(
        &'a self,
        token: &'a AccessToken,
    ) -> BoxFuture<'a, Result<TokenInfo, TokenInfoError>> {
        let start = Instant::now();
        self.metrics_collector.incoming_introspection_request();

        async move {
            let result = execute_once(
                &self.http_client,
                token,
                &self.url_prefix,
                &self.parser,
                &self.metrics_collector,
            ).await;

            match result {
                Ok(_) => {
                    self.metrics_collector.introspection_request(start);
                    self.metrics_collector.introspection_request_success(start);
                }
                Err(_) => {
                    self.metrics_collector.introspection_request(start);
                    self.metrics_collector.introspection_request_failure(start);
                }
            }

            result
        }
        .boxed()
    }

    fn introspect_with_retry<'a>(
        &'a self,
        token: &'a AccessToken,
        budget: Duration,
    ) -> BoxFuture<'a, Result<TokenInfo, TokenInfoError>> {
        let start = Instant::now();
        self.metrics_collector.incoming_introspection_request();

        let result = execute_with_retry(
            &self.http_client,
            token,
            &self.url_prefix,
            &self.parser,
            budget,
            &self.metrics_collector,
        );

        async move {
            let result = result.await;

            match result {
                Ok(_) => {
                    self.metrics_collector.introspection_request(start);
                    self.metrics_collector.introspection_request_success(start)
                }
                Err(_) => {
                    self.metrics_collector.introspection_request(start);
                    self.metrics_collector.introspection_request_failure(start)
                }
            }

            result
        }
        .boxed()
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

impl<P> AsyncTokenInfoServiceClientLight<P, DevNullMetricsCollector>
where
    P: TokenInfoParser + Send,
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
}

impl<P, M> AsyncTokenInfoServiceClientLight<P, M>
where
    P: TokenInfoParser + Send,
    M: MetricsCollector + Send,
{
    pub fn with_metrics(
        endpoint: &str,
        query_parameter: Option<&str>,
        fallback_endpoint: Option<&str>,
        parser: P,
        metrics_collector: M,
    ) -> InitializationResult<AsyncTokenInfoServiceClientLight<P, M>> {
        let url_prefix = assemble_url_prefix(endpoint, &query_parameter)
            .map_err(InitializationError)?;

        let fallback_url_prefix = if let Some(fallback_endpoint_address) = fallback_endpoint {
            Some(
                assemble_url_prefix(fallback_endpoint_address, &query_parameter)
                    .map_err(InitializationError)?,
            )
        } else {
            None
        };

        Ok(AsyncTokenInfoServiceClientLight {
            url_prefix: Arc::new(url_prefix),
            fallback_url_prefix: fallback_url_prefix.map(Arc::new),
            parser,
            metrics_collector,
        })
    }

    /// Creates an `AsyncTokenInfoService` with the given HttpClient
    pub fn with_client(
        &self,
        http_client: Client,
    ) -> AsyncTokenInfoServiceClient<P, M>
    where
        P: Clone,
        M: Clone,
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
    pub fn with_default_client(&self) -> InitializationResult<AsyncTokenInfoServiceClient<P, M>>
    where
        P: Clone,
        M: Clone,
    {
        let http_client = default_http_client()?;

        Ok(self.with_client(http_client))
    }
}

/// Creates a default HTTPS client
pub fn default_http_client() -> Result<HttpClient, InitializationError> {
    Client::builder()
        .build()
        .map_err(|err| InitializationError(err.to_string()))
}

impl<P, M> AsyncTokenInfoServiceLight for AsyncTokenInfoServiceClientLight<P, M>
where
    P: TokenInfoParser + Send + Sync,
    M: MetricsCollector + Send + Sync,
{
    fn introspect<'a>(
        &'a self,
        token: &'a AccessToken,
        http_client: &'a Client,
    ) -> BoxFuture<'a, Result<TokenInfo, TokenInfoError>> {
        let start = Instant::now();
        self.metrics_collector.incoming_introspection_request();

        async move {
            let result = execute_once(
                http_client,
                token,
                &self.url_prefix,
                &self.parser,
                &self.metrics_collector,
            ).await;

            match result {
                Ok(_) => {
                    self.metrics_collector.introspection_request(start);
                    self.metrics_collector.introspection_request_success(start)
                }
                Err(_) => {
                    self.metrics_collector.introspection_request(start);
                    self.metrics_collector.introspection_request_failure(start)
                }
            }

            result
        }
        .boxed()
    }

    fn introspect_with_retry<'a>(
        &'a self,
        token: &'a AccessToken,
        budget: Duration,
        http_client: &'a Client,
    ) -> BoxFuture<'a, Result<TokenInfo, TokenInfoError>> {
        let start = Instant::now();
        self.metrics_collector.incoming_introspection_request();

        async move {
            let result = execute_with_retry(
                http_client,
                token,
                &self.url_prefix,
                &self.parser,
                budget,
                &self.metrics_collector,
            ).await;

            match result {
                Ok(_) => {
                    self.metrics_collector.introspection_request(start);
                    self.metrics_collector.introspection_request_success(start)
                }
                Err(_) => {
                    self.metrics_collector.introspection_request(start);
                    self.metrics_collector.introspection_request_failure(start)
                }
            }

            result
        }
        .boxed()
    }
}

fn process_response<P>(
    response: Response,
    parser: &'_ P,
) -> BoxFuture<'_, Result<TokenInfo, TokenInfoError>>
where
    P: TokenInfoParser + Send + Sync,
{
    let status = response.status();

    async move {
        let body = response.bytes().await
            .map_err(|err| TokenInfoErrorKind::Io(format!("Could not get body chunks: {}", err)))?;

        if status == StatusCode::OK {
            match parser.parse(&body) {
                Ok(info) => Ok(info),
                Err(err) => {
                    let msg: String = String::from_utf8_lossy(&body).into();
                    Err(TokenInfoErrorKind::InvalidResponseContent(format!(
                        "{}: {}",
                        err, msg
                    )))
                }
            }
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
        .map_err(Into::into)
    }
    .boxed()
}

fn execute_with_retry<'a, M, P>(
    http_client: &'a Client,
    token: &'a AccessToken,
    url_prefix: &'a str,
    parser: &'a P,
    budget: Duration,
    metrics_collector: &'a M,
) -> impl Future<Output = Result<TokenInfo, TokenInfoError>> + Send + 'a
where
    P: TokenInfoParser + Send + Sync,
    M: MetricsCollector + Send + Sync,
{
    if budget == Duration::from_secs(0) {
        return future::err(
            TokenInfoErrorKind::Other("Initial reuest budget was 0".into()).into(),
        ).boxed();
    }

    let deadline = Instant::now() + budget;

    let mut backoff = backoff::ExponentialBackoff::default();
    backoff.max_elapsed_time = Some(Duration::from_millis(200));
    backoff.initial_interval = Duration::from_millis(10);
    backoff.multiplier = 1.5;

    let mut attempt = 1;

    let action = move || {
        let execution_result = execute_once(
            http_client,
            token,
            url_prefix,
            parser,
            metrics_collector,
        );

        async move {
            let result = if Instant::now() <= deadline {
                execution_result.await
            } else {
                Err(TokenInfoErrorKind::BudgetExceeded.into())
            };

            result.map_err(|err| {
                warn!(
                    "Attempt({}) on token introspection service. Reason: {}",
                    attempt, err
                );
                attempt += 1;

                if Instant::now() <= deadline && err.is_retry_suggested() {
                    backoff::Error::Transient(err)
                } else {
                    backoff::Error::Permanent(err)
                }
            })
        }
    };

    async move {
        action.with_backoff(&mut backoff).await.map_err(|err| match err {
            backoff::Error::Transient(err) => err,
            backoff::Error::Permanent(err) => err,
        })
    }
    .boxed()
}

fn execute_once<'a, P, M>(
    client: &'a Client,
    token: &'a AccessToken,
    url_prefix: &str,
    parser: &'a P,
    metrics_collector: &'a M,
) -> impl Future<Output = Result<TokenInfo, TokenInfoError>> + Send + 'a
where
    P: TokenInfoParser + Send + Sync,
    M: MetricsCollector + Send + Sync,
{
    let start = Instant::now();
    let uri = complete_url(url_prefix, &token);

    async move {
        let uri = uri?;

        match client.get(uri).send().await {
            Ok(response) => {
                metrics_collector.introspection_service_call(start);
                metrics_collector.introspection_service_call_success(start);
                process_response(response, parser).await
            }
            Err(err) => {
                metrics_collector.introspection_service_call(start);
                metrics_collector.introspection_service_call_failure(start);
                Err(err.into())
            }
        }
    }
}

fn complete_url(url_prefix: &str, token: &AccessToken) -> TokenInfoResult<Url> {
    let mut url_str = url_prefix.to_string();
    url_str.push_str(token.0.as_ref());
    let url = url_str.parse()?;
    Ok(url)
}

impl From<reqwest::Error> for TokenInfoError {
    fn from(err: reqwest::Error) -> Self {
        TokenInfoErrorKind::Other(err.to_string()).into()
    }
}
