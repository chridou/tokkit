mod errors;
mod parsers;

pub use self::errors::*;

/// Credentials of the resource Owner
/// required for the Access Token Request
pub struct UserCredentials {
    /// The resource owner username
    pub username: String,
    /// The resource owner password
    pub password: String,
}

/// Credentials of the registered client
/// to POST an Authorization Request
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
    pub user_credentials: UserCredentials,
}

pub trait CredentialsProvider {
    fn credentials(&self) -> CredentialsResult<CredentialsError>;
}

pub struct SplitFileCredentialsProvider {
    client_file_path: String,
    user_file_path: String,
}
