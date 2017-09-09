extern crate tokkit;

use std::thread;
use std::time::Duration;
use std::fmt;

use tokkit::*;
use tokkit::token_manager::*;
use tokkit::token_manager::token_provider::*;
use tokkit::token_manager::token_provider::credentials::*;

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
fn main() {
    let credentials_provider = SplitFileCredentialsProvider::with_default_client_parser_from_env(
        parsers::ApplicationResourceOwnerCredentialsParser,
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

    loop {
        let access_token_result = token_source.get_access_token(&MyTokenIdentifier);

        println!("Current token: {:?}", access_token_result);

        thread::sleep(Duration::from_millis(1000))
    }
}
