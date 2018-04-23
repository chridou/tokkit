use std::time::Duration;
use std::rc::Rc;

use futures::*;
use tokio_core::reactor::Handle;

use hyper;
use hyper::{Response, StatusCode, Uri};
use hyper_tls;

use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use {AccessToken, InitializationError, InitializationResult, TokenInfo};
use parsers::*;
use {TokenInfoError, TokenInfoErrorKind, TokenInfoResult};
use client::assemble_url_prefix;

type HttpClient = hyper::Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>>;

/// Gives a `TokenInfo` for an `AccessToken`.
///
/// See [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
pub trait AsyncTokenInfoService {
    /// Gives a `TokenInfo` for an `AccessToken`.
    fn introspect(
        &self,
        token: &AccessToken,
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError>>;
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

        let client = ::hyper::Client::configure()
            .connector(::hyper_tls::HttpsConnector::new(4, handle)?)
            .build(handle);

        Ok(AsyncTokenInfoServiceClient {
            url_prefix: Rc::new(url_prefix),
            fallback_url_prefix: fallback_url_prefix.map(|fb| Rc::new(fb)),
            http_client: Rc::new(client),
            parser: Rc::new(parser),
        })
    }
}

impl AsyncTokenInfoService for AsyncTokenInfoServiceClient {
    fn introspect(
        &self,
        token: &AccessToken,
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError>> {
        execute_once(
            self.http_client.clone(),
            token.clone(),
            &self.url_prefix,
            self.parser.clone(),
        )
    }

    fn introspect_with_retry(
        &self,
        token: &AccessToken,
        budget: Duration,
    ) -> Box<Future<Item = TokenInfo, Error = TokenInfoError>> {
        if budget == Duration::from_secs(0) {
            return Box::new(future::err(
                TokenInfoErrorKind::Other("Initial reuest budget was 0".into()).into(),
            ));
        }

        let retry_fut = {
            let token = token.clone();
            let http_client = self.http_client.clone();

            let url_prefix = self.url_prefix.clone();
            let parser = self.parser.clone();

            let retry_strategy = ExponentialBackoff::from_millis(10).map(jitter).take(3);
            let action = move || {
                execute_once(
                    http_client.clone(),
                    token.clone(),
                    &url_prefix.clone(),
                    parser.clone(),
                )
            };

            let future =
                Retry::spawn(retry_strategy, action).map_err(|retry_err| match retry_err {
                    ::tokio_retry::Error::OperationError(op_err) => op_err,
                    ::tokio_retry::Error::TimerError(err) => {
                        TokenInfoErrorKind::Io(format!("Retry Timer Error: {} ", err)).into()
                    }
                });
            future
        };

        Box::new(retry_fut)
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

fn execute_once(
    client: Rc<HttpClient>,
    token: AccessToken,
    url_prefix: &str,
    parser: Rc<TokenInfoParser + 'static>,
) -> Box<Future<Item = TokenInfo, Error = TokenInfoError>> {
    let f = future::result(complete_url(url_prefix, &token))
        .and_then(move |uri| client.get(uri).map_err(Into::into))
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
