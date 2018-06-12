use super::*;

use std::rc::Rc;
use std::thread;
use std::time::{Duration, Instant};

use futures::sync::{mpsc, oneshot};
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

/// An `AsyncTokenInfoService` that uses it's own reactor
#[derive(Clone)]
pub struct StandAloneAsyncTokenInfoServiceClient {
    sender: mpsc::Sender<(
        AccessToken,
        oneshot::Sender<Result<TokenInfo, TokenInfoError>>,
    )>,
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
        Self::with_metrics(
            endpoint,
            query_parameter,
            fallback_endpoint,
            parser,
            DevNullMetricsCollector,
        )
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
        M: MetricsCollector + Send + 'static,
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

        let (tx, rx) = mpsc::channel(1000);

        start_background_tokkit(
            url_prefix,
            fallback_url_prefix,
            parser,
            metrics_collector,
            rx,
        );

        Ok(StandAloneAsyncTokenInfoServiceClient { sender: tx })
    }
}

impl AsyncTokenInfoService for StandAloneAsyncTokenInfoServiceClient {
    fn introspect(
        &self,
        token: &AccessToken,
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError>> {
        unimplemented!()
    }

    fn introspect_with_retry(
        &self,
        token: &AccessToken,
        budget: Duration,
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError>> {
        let (tx, rx) = oneshot::channel();

        let mut sender = self.sender.clone();

        match sender.try_send((token.clone(), tx)) {
            Ok(_) => Box::new(rx.then(|res| match res {
                Ok(token_res) => token_res,
                Err(_) => Err(TokenInfoErrorKind::Other("The future was cancelled".into()).into()),
            })),
            Err(err) => {
                warn!("Failed to send token request: {}", err);
                Box::new(future::err(
                    TokenInfoErrorKind::Other("Failed to send token request".into()).into(),
                ))
            }
        }
    }
}

fn start_background_tokkit<P, M>(
    url_prefix: String,
    fallback_url_prefix: Option<String>,
    parser: P,
    metrics_collector: M,
    rx: mpsc::Receiver<(
        AccessToken,
        oneshot::Sender<Result<TokenInfo, TokenInfoError>>,
    )>,
) where
    P: TokenInfoParser + Send + 'static,
    M: MetricsCollector + Send + 'static,
{
    let _ = thread::Builder::new()
        .name("tokkit".to_string())
        .spawn(move || {
            let mut core = Core::new().unwrap();

            let http_client = ::hyper::Client::configure()
                .connector(::hyper_tls::HttpsConnector::new(4, &core.handle()).unwrap())
                .build(&core.handle());

            let introspector = AsyncTokenInfoServiceClient {
                url_prefix: Rc::new(url_prefix),
                fallback_url_prefix: fallback_url_prefix.map(|fb| Rc::new(fb)),
                parser: Rc::new(parser),
                metrics_collector: Rc::new(metrics_collector),
                http_client: Rc::new(http_client),
            };

            let h = core.handle();
            let f = rx.for_each(|(token, sender)| {
                let f = introspector
                    .introspect_with_retry(&token, Duration::from_secs(1))
                    .then(|res| match sender.send(res) {
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
                h.spawn(f);
                Ok(())
            });

            core.run(f).unwrap();
        });
}
