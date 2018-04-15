use std::time::Duration;
use std::rc::Rc;

use futures::*;
use tokio_core::reactor::Handle;

use hyper;
use hyper_tls;

use {AccessToken, InitializationError, InitializationResult, TokenInfo};
use parsers::*;
use {TokenInfoError, TokenInfoErrorKind, TokenInfoResult, TokenInfoService};
use client::assemble_url_prefix;

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

pub struct AsyncTokenInfoServiceClient {
    url_prefix: Rc<String>,
    fallback_url_prefix: Option<Rc<String>>,
    http_client: hyper::Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>>,
    parser: Rc<TokenInfoParser + Send + 'static>,
    handle: Handle,
}

impl AsyncTokenInfoServiceClient {
    pub fn new<P>(
        endpoint: &str,
        query_parameter: Option<&str>,
        fallback_endpoint: Option<&str>,
        parser: P,
        handle: Handle,
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
            .connector(::hyper_tls::HttpsConnector::new(4, &handle).unwrap())
            .build(&handle);

        Ok(AsyncTokenInfoServiceClient {
            url_prefix: Rc::new(url_prefix),
            fallback_url_prefix: fallback_url_prefix.map(|fb| Rc::new(fb)),
            http_client: client,
            parser: Rc::new(parser),
            handle,
        })
    }
}

impl AsyncTokenInfoService for AsyncTokenInfoServiceClient {
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
        unimplemented!()
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
