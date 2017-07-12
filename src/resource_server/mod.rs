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
#[derive(Debug, PartialEq)]
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

    pub struct PlanBTokenInfoParser;

    impl TokenInfoParser for PlanBTokenInfoParser {
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
                    Some(&JsonValue::Short(ref user_id)) => Some(UserId::new(user_id.as_ref())),
                    None => None,
                    invalid => {
                        bail!(format!(
                            "Expected a string as the user id in field '{}' but found a {:?}",
                            user_id_field,
                            invalid
                        ))
                    }
                };
                let scopes = match data.get(scopes_field) {
                    Some(&JsonValue::Array(ref values)) => {
                        let mut scopes = Vec::with_capacity(values.len());
                        for elem in values {
                            match elem {
                                &JsonValue::String(ref v) => scopes.push(Scope(v.clone())),
                                &JsonValue::Short(ref v) => scopes.push(Scope::new(v.as_ref())),
                                invalid => {
                                    bail!(format!(
                                        "Expected a string as a scope in ['{}'] but found '{}'",
                                        scopes_field,
                                        invalid
                                    ))
                                }
                            }
                        }
                        scopes
                    }
                    None => Vec::new(),
                    invalid => {
                        bail!(format!(
                            "Expected an array for the scopes in field '{}' but found a {:?}",
                            scopes_field,
                            invalid
                        ))
                    }
                };
                let expires_in = match data.get(expires_field) {
                    Some(&JsonValue::Number(number)) => {
                        let expires: f64 = number.into();
                        let expires = expires.round() as i64;
                        if expires >= 0 {
                            expires as u64
                        } else {
                            bail!(format!(
                                "Field '{}' for expires_in_seconds \
                                must be greater than 0(is {}).",
                                expires_field,
                                expires
                            ))
                        }
                    }
                    None => {
                        bail!(format!(
                            "Field '{}' for expires_in_seconds not found.",
                            expires_field
                        ))
                    }
                    invalid => bail!(format!(
                        "Expected a number for field '{}' but found a {:?}",
                        expires_field,
                        invalid)),
                };
                Ok(TokenInfo {
                    user_id: user_id,
                    scopes: scopes,
                    expires_in_seconds: expires_in,
                })
            }
            Ok(_) => Err(
                "Expected an object but found something else which i won't show\
                since it might contain a token.".to_string()),
            Err(err) => Err(err.to_string()),
        }
    }

    #[test]
    fn parse_plan_b_token_info_full() {
        let sample = br#"
        {
            "access_token": "token",
            "cn": true,
            "expires_in": 28292,
            "grant_type": "password",
            "open_id": "token",
            "realm": "/services",
            "scope": ["cn"],
            "token_type": "Bearer",
            "uid": "test2"
        }"#;

        let expected = TokenInfo {
            user_id: Some(UserId::new("test2")),
            scopes: vec!(Scope::new("cn")),
            expires_in_seconds: 28292,
        };

        let token_info = PlanBTokenInfoParser.parse(sample).unwrap();

        assert_eq!(expected, token_info);
    }
}
