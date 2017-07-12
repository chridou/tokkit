use std::fmt;

pub mod errors;
mod remote_server;

use self::errors::*;
pub use shared::*;

pub trait AuthorizationServer {
    /// Authenticate a user by Token.
    fn authenticate(&self, token: &Token) -> Result<AuthenticatedUser>;
}

/// An id that uniquely identifies the owner of a resource
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct Uid(pub String);

impl Uid {
    pub fn new<T: Into<String>>(uid: T) -> Uid {
        Uid(uid.into())
    }
}

impl fmt::Display for Uid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Once a user has been authenticated this struct can be used for authorization.
#[derive(Debug)]
pub struct AuthenticatedUser {
    pub uid: Uid,
    pub scopes: Vec<Scope>,
}

impl AuthenticatedUser {
    pub fn new(uid: Uid) -> Self {
        AuthenticatedUser {
            uid: uid,
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
    pub fn authorize(&self, scope: &Scope) -> ::std::result::Result<(), NotAuthorized> {
        if self.has_scope(scope) {
            Ok(())
        } else {
            Err(NotAuthorized(format!(
                "User with uid {} does not have the required scope {}.",
                self.uid,
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

fn json_to_user(json: &str) -> Result<AuthenticatedUser> {
    use json::*;
    match ::json::parse(json) {
        Ok(JsonValue::Object(data)) => {
            let uid = if let Some(&JsonValue::String(ref uid)) = data.get("uid") {
                Uid::new(uid.as_ref())
            } else {
                bail!(ErrorKind::InvalidResponseContent(
                    "Expected a string as the uid".to_string(),
                ))
            };
            let scopes = if let Some(&JsonValue::Array(ref values)) = data.get("scopes") {
                let mut scopes = Vec::with_capacity(values.len());
                for elem in values {
                    match elem {
                        &JsonValue::String(ref v) => scopes.push(Scope(v.clone())),
                        invalid => {
                            bail!(ErrorKind::InvalidResponseContent(format!(
                                "Expected a string as a scope but found '{}'",
                                invalid
                            )))
                        }
                    }
                }
                scopes
            } else {
                bail!(ErrorKind::InvalidResponseContent(
                    "Expected an array for scopes".to_string(),
                ))
            };
            Ok(AuthenticatedUser {
                uid: uid,
                scopes: scopes,
            })
        }
        Ok(invalid_value) => Err(
            ErrorKind::InvalidResponseContent(
                format!("Expected an object but found {}", invalid_value),
            ).into(),
        ),
        Err(err) => Err(ErrorKind::InvalidResponseContent(format!("{}", err)).into()),
    }
}
