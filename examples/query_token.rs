extern crate env_logger;
extern crate tokkit;

use std::thread;
use std::time::Duration;
use std::fmt;

use tokkit::token_manager::*;
use tokkit::token_manager::token_provider::*;
use tokkit::token_manager::token_provider::credentials::*;
use tokkit::token_manager::token_provider::credentials::parsers::*;
use tokkit::token_info::*;

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct MyTokenIdentifier;

impl fmt::Display for MyTokenIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MyTokenIdentifier")
    }
}

/// You have to set the following env vars:
///
/// * `TOKKIT_MANAGED_TOKEN_SCOPES`
/// * `CREDENTIALS_DIR`
/// * `TOKKIT_CREDENTIALS_RESOURCE_OWNER_FILENAME`
/// * `TOKKIT_CREDENTIALS_CLIENT_FILENAME`
/// * ´TOKKIT_AUTHORIZATION_SERVER_URL´
/// * ´TOKKIT_AUTHORIZATION_SERVER_REALM´
/// * ´TOKKIT_TOKEN_INTROSPECTION_ENDPOINT´
fn main() {
    env_logger::init().unwrap();

    let credentials_provider = SplitFileCredentialsProvider::with_default_client_parser_from_env(
        ApplicationResourceOwnerCredentialsParser,
    ).unwrap();

    let token_provider =
        ResourceOwnerPasswordCredentialsGrantProvider::from_env_with_credentials_provider(
            credentials_provider,
        ).unwrap();

    let mut managed_token_builder = ManagedTokenBuilder::default();
    managed_token_builder
        .with_identifier(MyTokenIdentifier)
        .with_scopes_from_env()
        .unwrap();
    let managed_token = managed_token_builder.build().unwrap();

    let mut token_group_builder = ManagedTokenGroupBuilder::default();
    token_group_builder
        .with_managed_token(managed_token)
        .with_token_provider(token_provider)
        .with_refresh_threshold(0.01);

    let token_group = token_group_builder.build().unwrap();

    let token_source = AccessTokenManager::start(vec![token_group]).unwrap();

    let builder = RemoteTokenInfoServiceBuilder::plan_b_from_env().unwrap();
    let introspection_service = builder.build().unwrap();

    loop {
        match token_source.get_access_token(&MyTokenIdentifier) {
            Ok(access_token) => {
                let token_info_result = introspection_service.introspect(&access_token);
                println!("{:?}", token_info_result);
            }
            Err(err) => println!("Invalid token: {}", err),
        }
        thread::sleep(Duration::from_millis(60_000))
    }
}
