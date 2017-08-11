use std::time::Instant;

mod errors;

pub use self::errors::*;
use super::{AccessToken, Scope};

pub type TokenServiceResult = Result<TokenServiceResponse, TokenServiceError>;

pub struct TokenServiceResponse {
    pub token: AccessToken,
    pub expires_at: Instant,
}

pub trait TokenService {
    fn get_token(&self, scopes: &[Scope]) -> TokenServiceResult;
}
