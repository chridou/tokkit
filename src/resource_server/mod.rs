use std::fmt;

pub mod errors;
mod server;

use self::errors::*;
pub use shared::*;

pub trait TokenInfoParser: 'static {
    fn parse(&self, bytes: &[u8]) -> ::std::result::Result<TokenInfo, String>;
}

impl TokenInfoParser for Fn(&[u8]) -> ::std::result::Result<TokenInfo, String> {
    fn parse(&self, bytes: &[u8]) -> ::std::result::Result<TokenInfo, String> {
        self(bytes)
    }
}

pub trait TokenInfoService {
    /// Authenticate a user by Token.
    fn get_token_info(&self, token: &Token) -> Result<TokenInfo>;

    fn authenticate_user(&self, token: &Token) -> Result<AuthenticatedUser> {
        let authenticated = self.get_token_info(token)?;
        if let Some(user_id) = authenticated.user_id {
            Ok({
                AuthenticatedUser {
                    user_id: user_id,
                    scopes: authenticated.scopes,
                }
            })
        } else {
            bail!(ErrorKind::NotAUser(
                "User id is missing in token info".to_string(),
            ))
        }
    }
}

/// An id that uniquely identifies the owner of a resource
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct UserId(pub String);

impl UserId {
    pub fn new<T: Into<String>>(uid: T) -> UserId {
        UserId(uid.into())
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Once a user has been authenticated this struct can be used for authorization.
#[derive(Debug)]
pub struct TokenInfo {
    pub user_id: Option<UserId>,
    pub scopes: Vec<Scope>,
    pub expires_in_seconds: u64,
}

/// Once a user has been authenticated this struct can be used for authorization.
#[derive(Debug)]
pub struct AuthenticatedUser {
    pub user_id: UserId,
    pub scopes: Vec<Scope>,
}

impl AuthenticatedUser {
    pub fn new(user_id: UserId) -> Self {
        AuthenticatedUser {
            user_id: user_id,
            scopes: Vec::new(),
        }
    }

    /// Use for authorization. Checks whether this user has the given Scope.
    pub fn has_scope(&self, scope: &Scope) -> bool {
        self.scopes.iter().find(|&s| s == scope).is_some()
    }

    /// Use for authorization. Checks whether this user has all of the given Scopes.
    pub fn has_scopes(&self, scopes: &[Scope]) -> bool {
        scopes.iter().all(|scope| self.has_scope(scope))
    }

    /// Authorize the user for an action defined by the given scope.
    /// If the user does not have the scope this method will fail.
    pub fn must_have_scope(&self, scope: &Scope) -> ::std::result::Result<(), NotAuthorized> {
        if self.has_scope(scope) {
            Ok(())
        } else {
            Err(NotAuthorized(format!(
                "User '{}' does not have the required scope '{}'.",
                self.user_id,
                scope
            )))
        }
    }
}

#[derive(Debug)]
pub struct NotAuthorized(String);

impl NotAuthorized {
    pub fn new<T: Into<String>>(msg: T) -> NotAuthorized {
        NotAuthorized(msg.into())
    }
}

impl fmt::Display for NotAuthorized {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Not authorized: {}", self.0)
    }
}

impl ::std::error::Error for NotAuthorized {
    fn description(&self) -> &str {
        "not authorized"
    }

    fn cause(&self) -> Option<&::std::error::Error> {
        None
    }
}

mod parsers {
    use super::*;
    use std::str;

    pub struct PlanBParser;

    impl TokenInfoParser for PlanBParser {
        fn parse(&self, json: &[u8]) -> ::std::result::Result<TokenInfo, String> {
            parse(json, "uid", "scope", "expires_in")
        }
    }

    fn parse(
        json: &[u8],
        user_id_field: &str,
        scopes_field: &str,
        expires_field: &str,
    ) -> ::std::result::Result<TokenInfo, String> {
        use json::*;
        let json = str::from_utf8(json).map_err(|err| err.to_string())?;
        match ::json::parse(json) {
            Ok(JsonValue::Object(data)) => {
                let user_id = match data.get(user_id_field) {
                    Some(&JsonValue::String(ref user_id)) => Some(UserId::new(user_id.as_ref())),
                    None => None,
                    _ => bail!("Expected a string as the uid".to_string()),
                };
                let scopes = match data.get(scopes_field) {
                    Some(&JsonValue::Array(ref values)) => {
                        let mut scopes = Vec::with_capacity(values.len());
                        for elem in values {
                            match elem {
                                &JsonValue::String(ref v) => scopes.push(Scope(v.clone())),
                                invalid => {
                                    bail!(format!(
                                        "Expected a string as a scope but found '{}'",
                                        invalid
                                    ))
                                }
                            }
                        }
                        scopes
                    }
                    None => Vec::new(),
                    _ => bail!("Expected an array for the scopes".to_string()),
                };
                let expires_in = match data.get(expires_field) {
                    Some(&JsonValue::Number(number)) => {
                        let f: f64 = number.into();

                        0u64
                    }
                    None => {
                        bail!(format!(
                            "Field '{}' for expires in not found.",
                            expires_field
                        ))
                    }
                    _ => bail!("Expected a number for expires in".to_string()),
                };
                Ok(TokenInfo {
                    user_id: user_id,
                    scopes: scopes,
                    expires_in_seconds: expires_in,
                })
            }
            Ok(invalid_value) => Err(format!("Expected an object but found {}", invalid_value)),
            Err(err) => Err(err.to_string()),
        }
    }
}
