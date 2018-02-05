use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::env::{self, VarError};
use std::result::Result as StdResult;

use {InitializationError, InitializationResult};

mod errors;
pub mod parsers;

pub use self::errors::*;

use self::parsers::*;

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
    fn client_credentials(&self) -> CredentialsResult<ClientCredentials>;
    fn owner_credentials(&self) -> CredentialsResult<ResourceOwnerCredentials>;

    fn credentials(&self) -> CredentialsResult<RequestTokenCredentials> {
        let client_credentials = self.client_credentials()?;
        let owner_credentials = self.owner_credentials()?;
        Ok(RequestTokenCredentials {
            client_credentials,
            owner_credentials,
        })
    }
}

/// Reads the credentials for the resource owner and the client
/// from two seperate (mostly) JSON files.
pub struct SplitFileCredentialsProvider {
    client_credentials_file_path: PathBuf,
    owner_credentials_file_path: PathBuf,
    client_credentials_parser: Box<ClientCredentialsParser + Send + Sync + 'static>,
    owner_credentials_parser: Box<ResourceOwnerCredentialsParser + Send + Sync + 'static>,
}

impl SplitFileCredentialsProvider {
    /// Create a new instance with the given paths
    /// and the given parsers.
    pub fn new<C, O, CP, UP>(
        client_credentials_file_path: C,
        owner_credentials_file_path: O,
        client_credentials_parser: CP,
        owner_credentials_parser: UP,
    ) -> Self
    where
        C: Into<PathBuf>,
        O: Into<PathBuf>,
        CP: ClientCredentialsParser + Send + Sync + 'static,
        UP: ResourceOwnerCredentialsParser + Send + Sync + 'static,
    {
        SplitFileCredentialsProvider {
            client_credentials_file_path: client_credentials_file_path.into(),
            owner_credentials_file_path: owner_credentials_file_path.into(),
            client_credentials_parser: Box::new(client_credentials_parser),
            owner_credentials_parser: Box::new(owner_credentials_parser),
        }
    }

    /// Creates a new instance for the given path with default parsers.
    ///
    /// # Example files
    ///
    /// ## Client credentials file:
    ///
    /// ```javascript
    /// {
    ///    "client_id" : "<id>",
    ///    "client_secret" : "<secret>"
    /// }
    /// ```
    ///
    /// ## Resource owner credentials file:
    ///
    /// ```javascript
    /// {
    ///    "username" : "<id>",
    ///    "password" : "<secret>"
    /// }
    /// ```
    pub fn with_default_parsers<C, O>(
        client_credentials_file_path: C,
        owner_credentials_file_path: O,
    ) -> Self
    where
        C: Into<PathBuf>,
        O: Into<PathBuf>,
    {
        SplitFileCredentialsProvider::new(
            client_credentials_file_path,
            owner_credentials_file_path,
            DefaultClientCredentialsParser,
            DefaultResourceOwnerCredentialsParser,
        )
    }

    /// Creates a new instance for the given path with a default parser
    /// for the client credentials.
    ///
    /// # Example files
    ///
    /// ## Client credentials file:
    ///
    /// ```javascript
    /// {
    ///    "client_id" : "<id>",
    ///    "client_secret" : "<secret>"
    /// }
    /// ```
    pub fn with_default_client_parser<C, O, P>(
        client_credentials_file_path: C,
        owner_credentials_file_path: O,
        owner_credentials_parser: P,
    ) -> Self
    where
        C: Into<PathBuf>,
        O: Into<PathBuf>,
        P: ResourceOwnerCredentialsParser + Send + Sync + 'static,
    {
        SplitFileCredentialsProvider::new(
            client_credentials_file_path,
            owner_credentials_file_path,
            DefaultClientCredentialsParser,
            owner_credentials_parser,
        )
    }

    /// Configures from environment variables while the `ResourceOwnerCredentialsParser`
    /// can be explicitly set.
    ///
    /// * '`TOKKIT_CREDENTIALS_DIR`': The first place to look for the path to the credentials
    /// files.
    /// * '`CREDENTIALS_DIR`': The fallback for '`TOKKIT_CREDENTIALS_DIR`'
    /// * '`TOKKIT_CREDENTIALS_RESOURCE_OWNER_FILENAME`' : The file name for the resource owner
    /// credentials
    /// * '`TOKKIT_CREDENTIALS_CLIENT_FILENAME`' : The file name for the client credentials
    ///
    /// Either '`TOKKIT_CREDENTIALS_DIR`' or '`CREDENTIALS_DIR`' must be set where
    /// '`TOKKIT_CREDENTIALS_DIR`' takes preceedence.
    /// '`TOKKIT_CREDENTIALS_RESOURCE_OWNER_FILENAME`'
    /// defaults to `user.json` while '`TOKKIT_CREDENTIALS_CLIENT_FILENAME`' defaults to
    /// `client.json`.
    pub fn with_default_client_parser_from_env<P>(
        owner_credentials_parser: P,
    ) -> InitializationResult<Self>
    where
        P: ResourceOwnerCredentialsParser + Send + Sync + 'static,
    {
        let credentials_dir = credentials_dir_from_env().map_err(|msg| InitializationError(msg))?;

        let owner_file_name: PathBuf = match env::var("TOKKIT_CREDENTIALS_RESOURCE_OWNER_FILENAME")
        {
            Ok(dir) => dir.into(),
            Err(VarError::NotPresent) => {
                warn!("No owner file name. Assuming 'user.json'");
                "user.json".into()
            }
            Err(err) => bail!(err),
        };

        let client_file_name: PathBuf = match env::var("TOKKIT_CREDENTIALS_CLIENT_FILENAME") {
            Ok(dir) => dir.into(),
            Err(VarError::NotPresent) => {
                warn!("No client file name. Assuming 'client.json'");
                "client.json".into()
            }
            Err(err) => bail!(err),
        };

        let mut owner_credentials_file_path = credentials_dir.clone();
        owner_credentials_file_path.push(owner_file_name);

        let mut client_credentials_file_path = credentials_dir;
        client_credentials_file_path.push(client_file_name);

        info!(
            "Client credentials file path is '{}', owner credentials file path is '{}'.",
            client_credentials_file_path.display(),
            owner_credentials_file_path.display()
        );

        Ok(SplitFileCredentialsProvider::with_default_client_parser(
            client_credentials_file_path,
            owner_credentials_file_path,
            owner_credentials_parser,
        ))
    }

    /// Configures the instance from environment variables.
    ///
    /// * '`TOKKIT_CREDENTIALS_DIR`': The first place to look for the path to the credentials
    /// files.
    /// * '`CREDENTIALS_DIR`': The fallback for '`TOKKIT_CREDENTIALS_DIR`'
    /// * '`TOKKIT_CREDENTIALS_RESOURCE_OWNER_FILENAME`' : The file name for the resource owner
    /// credentials
    /// * '`TOKKIT_CREDENTIALS_CLIENT_FILENAME`' : The file name for the client credentials
    ///
    /// Either '`TOKKIT_CREDENTIALS_DIR`' or '`CREDENTIALS_DIR`' must be set where
    /// '`TOKKIT_CREDENTIALS_DIR`' takes preceedence.
    /// '`TOKKIT_CREDENTIALS_RESOURCE_OWNER_FILENAME`'
    /// defaults to `user.json` while '`TOKKIT_CREDENTIALS_CLIENT_FILENAME`' defaults to
    /// `client.json`.
    pub fn with_default_parsers_from_env() -> InitializationResult<Self> {
        SplitFileCredentialsProvider::with_default_client_parser_from_env(
            DefaultResourceOwnerCredentialsParser,
        )
    }
}

fn credentials_dir_from_env() -> StdResult<PathBuf, String> {
    match env::var("TOKKIT_CREDENTIALS_DIR") {
        Ok(dir) => Ok(dir.into()),
        Err(VarError::NotPresent) => {
            info!("'TOKKIT_CREDENTIALS_DIR' not found. Looking for 'CREDENTIALS_DIR'");
            match env::var("CREDENTIALS_DIR") {
                Ok(dir) => Ok(dir.into()),
                Err(VarError::NotPresent) => {
                    Err("Path for credentials files not found. Please \
                         set 'TOKKIT_CREDENTIALS_DIR' or 'CREDENTIALS_DIR'."
                        .into())
                }
                Err(err) => Err(err.to_string()),
            }
        }
        Err(err) => Err(err.to_string()),
    }
}

impl CredentialsProvider for SplitFileCredentialsProvider {
    fn client_credentials(&self) -> CredentialsResult<ClientCredentials> {
        let mut file = File::open(&self.client_credentials_file_path)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        self.client_credentials_parser.parse(&contents)
    }

    fn owner_credentials(&self) -> CredentialsResult<ResourceOwnerCredentials> {
        let mut file = File::open(&self.owner_credentials_file_path)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        self.owner_credentials_parser.parse(&contents)
    }
}
