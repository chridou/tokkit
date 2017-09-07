use std::fs::File;
use std::io::prelude::*;

mod errors;
pub mod parsers;

pub use self::errors::*;

use self::parsers::{ClientCredentialsParser, ResourceOwnerCredentialsParser};

/// Credentials of the resource Owner
/// required for the Access Token Request
///
/// # [RFC6449 Sec. 1.3.3](https://tools.ietf.org/html/rfc6749#section-1.3.3)
///
/// The resource owner password credentials (i.e., username and password)
/// can be used directly as an authorization grant to obtain an access
/// token.  The credentials should only be used when there is a high
/// degree of trust between the resource owner and the client (e.g., the
/// client is part of the device operating system or a highly privileged
/// application), and when other authorization grant types are not
/// available (such as an authorization code).
///
/// Even though this grant type requires direct client access to the
/// resource owner credentials, the resource owner credentials are used
/// for a single request and are exchanged for an access token.  This
/// grant type can eliminate the need for the client to store the
/// resource owner credentials for future use, by exchanging the
/// credentials with a long-lived access token or refresh token.
pub struct ResourceOwnerCredentials {
    /// The resource owner username
    pub username: String,
    /// The resource owner password
    pub password: String,
}

/// Credentials of the registered client
/// to POST an Authorization Request
///
/// # [RFC6449 Sec. 1.3.4](https://tools.ietf.org/html/rfc6749#section-1.3.3)
///
/// The client credentials (or other forms of client authentication) can
/// be used as an authorization grant when the authorization scope is
/// limited to the protected resources under the control of the client,
/// or to protected resources previously arranged with the authorization
/// server.  Client credentials are used as an authorization grant
/// typically when the client is acting on its own behalf (the client is
/// also the resource owner) or is requesting access to protected
/// resources based on an authorization previously arranged with the
/// authorization server.
pub struct ClientCredentials {
    /// The id of the client to authenticate with
    /// the authorization service.
    pub client_id: String,
    /// The password of the client to authenticate with
    /// the authorization service
    pub client_secret: String,
}


pub struct RequestTokenCredentials {
    pub client_credentials: ClientCredentials,
    pub owner_credentials: ResourceOwnerCredentials,
}

pub trait CredentialsProvider {
    fn credentials(&self) -> CredentialsResult<RequestTokenCredentials>;
}

pub struct SplitFileCredentialsProvider {
    client_credentials_file_path: String,
    owner_credentials_file_path: String,
    client_credentials_parser: Box<ClientCredentialsParser>,
    owner_credentials_parser: Box<ResourceOwnerCredentialsParser>,
}

impl SplitFileCredentialsProvider {
    pub fn new<C, U>(
        client_credentials_file_path: String,
        owner_credentials_file_path: String,
        client_credentials_parser: C,
        owner_credentials_parser: U,
    ) -> Self
    where
        C: ClientCredentialsParser + 'static,
        U: ResourceOwnerCredentialsParser + 'static,
    {
        SplitFileCredentialsProvider {
            client_credentials_file_path,
            owner_credentials_file_path,
            client_credentials_parser: Box::new(client_credentials_parser),
            owner_credentials_parser: Box::new(owner_credentials_parser),
        }
    }
}

impl CredentialsProvider for SplitFileCredentialsProvider {
    fn credentials(&self) -> CredentialsResult<RequestTokenCredentials> {
        let mut file = File::open(&self.client_credentials_file_path)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        let client_credentials = self.client_credentials_parser.parse(&contents)?;
        let mut file = File::open(&self.owner_credentials_file_path)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        let owner_credentials = self.owner_credentials_parser.parse(&contents)?;
        Ok(RequestTokenCredentials {
            owner_credentials,
            client_credentials,
        })
    }
}
