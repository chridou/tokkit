use std::rc::Rc;
use std::time::{Duration, Instant};

use futures::sync::oneshot;
use futures::*;
use hyper;
use hyper::{Response, StatusCode, Uri};
use hyper_tls;
use tokio_core::reactor::{Core, Handle};
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::RetryIf;

use client::assemble_url_prefix;
use metrics::{DevNullMetricsCollector, MetricsCollector};
use parsers::*;
use {AccessToken, InitializationError, InitializationResult, TokenInfo};
use {TokenInfoError, TokenInfoErrorKind, TokenInfoResult};

pub type HttpClient = hyper::Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>>;

/// Gives a `TokenInfo` for an `AccessToken`.
///
/// See [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
pub trait AsyncTokenInfoService {
    /// Gives a `TokenInfo` for an `AccessToken`.
    fn introspect(
        &self,
        token: &AccessToken,
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError>>;
    /// Gives a `TokenInfo` for an `AccessToken` with retries.
    ///
    /// `budget` defines the duration the retries may take
    /// until the whole call is considered a failure.
    fn introspect_with_retry(
        &self,
        token: &AccessToken,
        budget: Duration,
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError>>;
}

#[derive(Clone)]
pub struct AsyncTokenInfoServiceClient {
    url_prefix: Rc<String>,
    fallback_url_prefix: Option<Rc<String>>,
    http_client: Rc<HttpClient>,
    parser: Rc<TokenInfoParser + Send + 'static>,
    metrics_collector: Rc<MetricsCollector + 'static>,
}

impl AsyncTokenInfoServiceClient {
    pub fn new<P>(
        endpoint: &str,
        query_parameter: Option<&str>,
        fallback_endpoint: Option<&str>,
        parser: P,
        handle: &Handle,
    ) -> InitializationResult<AsyncTokenInfoServiceClient>
    where
        P: TokenInfoParser + Send + 'static,
    {
        AsyncTokenInfoServiceClient::with_metrics(
            endpoint,
            query_parameter,
            fallback_endpoint,
            parser,
            handle,
            DevNullMetricsCollector,
        )
    }

    pub fn with_metrics<P, M>(
        endpoint: &str,
        query_parameter: Option<&str>,
        fallback_endpoint: Option<&str>,
        parser: P,
        handle: &Handle,
        metrics_collector: M,
    ) -> InitializationResult<AsyncTokenInfoServiceClient>
    where
        P: TokenInfoParser + Send + 'static,
        M: MetricsCollector + 'static,
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

        let http_client = ::hyper::Client::configure()
            .connector(::hyper_tls::HttpsConnector::new(4, handle)?)
            .build(handle);

        let http_client = Rc::new(http_client);

        Ok(AsyncTokenInfoServiceClient {
            url_prefix: Rc::new(url_prefix),
            fallback_url_prefix: fallback_url_prefix.map(|fb| Rc::new(fb)),
            parser: Rc::new(parser),
            metrics_collector: Rc::new(metrics_collector),
            http_client,
        })
    }
}

impl AsyncTokenInfoService for AsyncTokenInfoServiceClient {
    fn introspect(
        &self,
        token: &AccessToken,
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError>> {
        let start = Instant::now();
        self.metrics_collector.incoming_introspection_request();

        let metrics_collector = self.metrics_collector.clone();
        let f = execute_once(
            self.http_client.clone(),
            token.clone(),
            &self.url_prefix,
            self.parser.clone(),
            self.metrics_collector.clone(),
        ).then(move |result| {
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
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError>> {
        let start = Instant::now();
        self.metrics_collector.incoming_introspection_request();

        let metrics_collector = self.metrics_collector.clone();
        let f = execute_with_retry(
            self.http_client.clone(),
            token.clone(),
            &self.url_prefix,
            self.parser.clone(),
            budget,
            self.metrics_collector.clone(),
        ).then(move |result| {
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

/// An `AsyncTokenInfoService` that uses it's own reactor
#[derive(Clone)]
pub struct StandAloneAsyncTokenInfoServiceClient {
    inner: AsyncTokenInfoServiceClient,
    core: Rc<Core>,
}

impl StandAloneAsyncTokenInfoServiceClient {
    pub fn new<P>(
        endpoint: &str,
        query_parameter: Option<&str>,
        fallback_endpoint: Option<&str>,
        parser: P,
    ) -> InitializationResult<StandAloneAsyncTokenInfoServiceClient>
    where
        P: TokenInfoParser + Send + 'static,
    {
        let core = Rc::new(Core::new().map_err(|err| {
            InitializationError(format!("Could not create reactor core: {}", err))
        })?);

        let inner = AsyncTokenInfoServiceClient::new(
            endpoint,
            query_parameter,
            fallback_endpoint,
            parser,
            &core.handle(),
        )?;

        Ok(StandAloneAsyncTokenInfoServiceClient { inner, core })
    }

    pub fn with_metrics<P, M>(
        endpoint: &str,
        query_parameter: Option<&str>,
        fallback_endpoint: Option<&str>,
        parser: P,
        metrics_collector: M,
    ) -> InitializationResult<StandAloneAsyncTokenInfoServiceClient>
    where
        P: TokenInfoParser + Send + 'static,
        M: MetricsCollector + 'static,
    {
        let core = Rc::new(Core::new().map_err(|err| {
            InitializationError(format!("Could not create reactor core: {}", err))
        })?);

        let inner = AsyncTokenInfoServiceClient::with_metrics(
            endpoint,
            query_parameter,
            fallback_endpoint,
            parser,
            &core.handle(),
            metrics_collector,
        )?;

        Ok(StandAloneAsyncTokenInfoServiceClient { inner, core })
    }
}

impl AsyncTokenInfoService for StandAloneAsyncTokenInfoServiceClient {
    fn introspect(
        &self,
        token: &AccessToken,
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError>> {
        let (tx, rx) = oneshot::channel();

        let f = self.inner
            .introspect(&token)
            .then(|res| match tx.send(res) {
                Ok(_) => Ok(()),
                Err(Ok(_)) => {
                    warn!(
                        "Failed to send a valid token info because the \
                         receiving end was already gone."
                    );
                    Err(())
                }
                Err(Err(err)) => {
                    error!(
                        "Failed to send token error result because the \
                         receiving end was already gone. The error was: {}",
                        err
                    );
                    Err(())
                }
            });

        Box::new(rx.then(|res| match res {
            Ok(token_res) => token_res,
            Err(_) => Err(TokenInfoErrorKind::Other("The future was cancelled".into()).into()),
        }))
    }

    fn introspect_with_retry(
        &self,
        token: &AccessToken,
        budget: Duration,
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError>> {
        let (tx, rx) = oneshot::channel();

        let f = self.inner
            .introspect_with_retry(&token, budget)
            .then(|res| match tx.send(res) {
                Ok(_) => Ok(()),
                Err(Ok(_)) => {
                    warn!(
                        "Failed to send a valid token info because the \
                         receiving end was already gone."
                    );
                    Err(())
                }
                Err(Err(err)) => {
                    error!(
                        "Failed to send token error result because the \
                         receiving end was already gone. The error was: {}",
                        err
                    );
                    Err(())
                }
            });

        Box::new(rx.then(|res| match res {
            Ok(token_res) => token_res,
            Err(_) => Err(TokenInfoErrorKind::Other("The future was cancelled".into()).into()),
        }))
    }
}

fn process_response(
    response: Response,
    parser: Rc<TokenInfoParser + 'static>,
) -> Box<Future<Item = TokenInfo, Error = TokenInfoError>> {
    let status = response.status();
    let f = response
        .body()
        .concat2()
        .map_err(|err| TokenInfoErrorKind::Io(format!("Could not get body chunks: {}", err)))
        .and_then(move |body_chunk| {
            if status == StatusCode::Ok {
                let result = match parser.parse(&body_chunk) {
                    Ok(info) => Ok(info),
                    Err(err) => {
                        let msg: String = String::from_utf8_lossy(&body_chunk).into();
                        Err(TokenInfoErrorKind::InvalidResponseContent(format!(
                            "{}: {}",
                            err, msg
                        )))
                    }
                };
                result
            } else if status == StatusCode::Unauthorized {
                let msg = String::from_utf8_lossy(&body_chunk);
                Err(TokenInfoErrorKind::NotAuthenticated(format!(
                    "The server refused the token: {}",
                    msg
                )))
            } else if status.is_client_error() {
                let msg = String::from_utf8_lossy(&body_chunk).into();
                Err(TokenInfoErrorKind::Client(msg))
            } else if status.is_server_error() {
                let msg = String::from_utf8_lossy(&body_chunk).into();
                Err(TokenInfoErrorKind::Server(msg))
            } else {
                let msg = String::from_utf8_lossy(&body_chunk).into();
                Err(TokenInfoErrorKind::Other(msg))
            }
        })
        .map_err(Into::into);

    Box::new(f)
}

fn execute_with_retry(
    http_client: Rc<HttpClient>,
    token: AccessToken,
    url_prefix: &str,
    parser: Rc<TokenInfoParser + 'static>,
    budget: Duration,
    metrics_collector: Rc<MetricsCollector>,
) -> Box<Future<Item = TokenInfo, Error = TokenInfoError>> {
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

fn execute_once(
    client: Rc<HttpClient>,
    token: AccessToken,
    url_prefix: &str,
    parser: Rc<TokenInfoParser + 'static>,
    metrics_collector: Rc<MetricsCollector>,
) -> Box<Future<Item = TokenInfo, Error = TokenInfoError>> {
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

impl From<hyper_tls::Error> for InitializationError {
    fn from(err: hyper_tls::Error) -> Self {
        InitializationError(format!("Could not initialize hyper_tls: {}", err))
    }
}

impl From<hyper::error::UriError> for TokenInfoError {
    fn from(err: hyper::error::UriError) -> Self {
        TokenInfoErrorKind::UrlError(err.to_string()).into()
    }
}

impl From<hyper::error::Error> for TokenInfoError {
    fn from(err: hyper::error::Error) -> Self {
        use hyper::error::Error::*;
        match err {
            Method => TokenInfoErrorKind::Other(err.to_string()).into(),
            Uri(err) => TokenInfoErrorKind::UrlError(err.to_string()).into(),
            Version => TokenInfoErrorKind::Other(err.to_string()).into(),
            Header => TokenInfoErrorKind::Other(err.to_string()).into(),
            TooLarge => TokenInfoErrorKind::Other(err.to_string()).into(),
            Incomplete => TokenInfoErrorKind::Other(err.to_string()).into(),
            Status => TokenInfoErrorKind::Other(err.to_string()).into(),
            Timeout => TokenInfoErrorKind::Server(err.to_string()).into(),
            Upgrade => TokenInfoErrorKind::Other(err.to_string()).into(),
            Cancel(err @ hyper::error::Canceled { .. }) => {
                TokenInfoErrorKind::Io(err.to_string()).into()
            }
            Closed => TokenInfoErrorKind::Io(err.to_string()).into(),
            Io(err) => TokenInfoErrorKind::Io(err.to_string()).into(),
            Utf8(err) => TokenInfoErrorKind::Io(err.to_string()).into(),
            err => TokenInfoErrorKind::Other(err.to_string()).into(),
        }
    }
}
