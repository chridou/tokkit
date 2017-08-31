//! Various parsers for the responses of a token info service.
use super::*;
use std::str;
use std::env;

/// A configurable `TokenInfoParser` that parses a `TokenInfo` from JSON
/// returned by a token introspection service.
pub struct CustomTokenInfoParser {
    /// The field name in the JSON that identifies the `active` field
    /// for the `TokenInfo`. If None the field will not be looked up
    /// and set to `true` in the `TokenInfo` right away.
    /// The reason is that this is a mandatory field in the `TokenInfo`
    /// and that we assume that if a token introspection service does
    /// not provide this field it would return an error in the introspection request
    /// in case the token is not active at the time the request was made.
    pub active_field: Option<String>,
    /// The field name in the JSON that identifies the `user_id` field
    /// for the `TokenInfo`. If None the field will not be looked up
    /// and set to `None` in the `TokenInfo` right away.
    pub user_id_field: Option<String>,
    /// The field name in the JSON that identifies the `scope` field
    /// for the `TokenInfo`. If None the field will not be looked up
    /// and set to `None` in the `TokenInfo` right away.
    pub scope_field: Option<String>,
    /// The field name in the JSON that identifies the `expires_in` field
    /// for the `TokenInfo`. If None the field will not be looked up
    /// and set to `None` in the `TokenInfo` right away.
    pub expires_in_field: Option<String>,
}

impl CustomTokenInfoParser {
    pub fn new<U, S, E, A>(
        active_field: Option<A>,
        user_id_field: Option<U>,
        scope_field: Option<S>,
        expires_in_field: Option<E>,
    ) -> Self
    where
        U: Into<String>,
        S: Into<String>,
        E: Into<String>,
        A: Into<String>,
    {
        Self {
            active_field: active_field.map(Into::into),
            user_id_field: user_id_field.map(Into::into),
            scope_field: scope_field.map(Into::into),
            expires_in_field: expires_in_field.map(Into::into),
        }
    }

    /// Create a new parser from environment variables.
    ///
    /// The following variables used to identify the field in a token info response:
    ///
    /// * `TOKKIT_TOKEN_INFO_PARSER_USER_ID_FIELD`(optional): The field name for the user id
    /// * `TOKKIT_TOKEN_INFO_PARSER_SCOPE_FIELD`(optional): The field name for scopes
    /// * `TOKKIT_TOKEN_INFO_PARSER_EXPIRES_IN_FIELD`(optional): The field name for the
    /// * `TOKKIT_TOKEN_INFO_PARSER_ACTIVE_FIELD`(optional): The field name for the
    /// active field
    pub fn from_env() -> InitializationResult<CustomTokenInfoParser> {
        let user_id_field: Option<String> =
            match env::var("TOKKIT_TOKEN_INFO_PARSER_USER_ID_FIELD") {
                Ok(v) => Ok(Some(v)),
                Err(VarError::NotPresent) => Ok(None),
                Err(err) => Err(InitializationError(
                    format!("'TOKKIT_TOKEN_INFO_PARSER_USER_ID_FIELD': {}", err),
                )),
            }?;
        let scope_field: Option<String> = match env::var("TOKKIT_TOKEN_INFO_PARSER_SCOPE_FIELD") {
            Ok(v) => Ok(Some(v)),
            Err(VarError::NotPresent) => Ok(None),
            Err(err) => Err(InitializationError(
                format!("'TOKKIT_TOKEN_INFO_PARSER_SCOPE_FIELD': {}", err),
            )),
        }?;
        let expires_in_field: Option<String> =
            match env::var("TOKKIT_TOKEN_INFO_PARSER_EXPIRES_IN_FIELD") {
                Ok(v) => Ok(Some(v)),
                Err(VarError::NotPresent) => Ok(None),
                Err(err) => Err(InitializationError(format!(
                    "'TOKKIT_TOKEN_INFO_PARSER_EXPIRES_IN_FIELD': {}",
                    err
                ))),
            }?;
        let active_field: Option<String> =
            match env::var("TOKKIT_TOKEN_INFO_PARSER_ACTIVE_FIELD") {
                Ok(v) => Ok(Some(v)),
                Err(VarError::NotPresent) => Ok(None),
                Err(err) => Err(InitializationError(
                    format!("'TOKKIT_TOKEN_INFO_PARSER_ACTIVE_FIELD': {}", err),
                )),
            }?;
        Ok(Self::new(
            active_field,
            user_id_field,
            scope_field,
            expires_in_field,
        ))
    }
}

impl TokenInfoParser for CustomTokenInfoParser {
    fn parse(&self, json: &[u8]) -> ::std::result::Result<TokenInfo, String> {
        parse(
            json,
            self.active_field.as_ref().map(|s| &**s),
            self.user_id_field.as_ref().map(|s| &**s),
            self.scope_field.as_ref().map(|s| &**s),
            self.expires_in_field.as_ref().map(|s| &**s),
        )
    }
}

/// Parses a `TokenInfo` from JSON
///
/// [Description](http://planb.readthedocs.io/en/latest/intro.html#token-info)
///
/// ##Example
///
/// ```rust
/// use tokkit::*;
/// use tokkit::token_info::*;
/// use tokkit::token_info::parsers::PlanBTokenInfoParser;
///
/// let sample = br#"
///     {
///         "access_token": "token",
///         "cn": true,
///         "expires_in": 28292,
///         "grant_type": "password",
///         "open_id": "token",
///         "realm": "/services",
///         "scope": ["cn"],
///         "token_type": "Bearer",
///         "uid": "test2"
///     }
///     "#;
///
/// let expected = TokenInfo {
///     active: true,
///     user_id: Some(UserId::new("test2")),
///     scope: vec![Scope::new("cn")],
///     expires_in_seconds: Some(28292),
/// };
///
/// let token_info = PlanBTokenInfoParser.parse(sample).unwrap();
///
/// assert_eq!(expected, token_info);
/// ```
pub struct PlanBTokenInfoParser;

impl TokenInfoParser for PlanBTokenInfoParser {
    fn parse(&self, json: &[u8]) -> ::std::result::Result<TokenInfo, String> {
        parse(json, None, Some("uid"), Some("scope"), Some("expires_in"))
    }
}

/// Parses a `TokenInfo` from JSON
///
/// [Description](https://developers.google.com/identity/protocols/OAuth2UserAgent#validatetoken)
///
/// ##Example
///
/// ```rust
/// use tokkit::*;
/// use tokkit::token_info::*;
/// use tokkit::token_info::parsers::GoogleV3TokenInfoParser;
///
/// let sample = br#"
/// {
///     "aud":"8819981768.apps.googleusercontent.com",
///     "user_id":"123456789",
///     "scope":"https://www.googleapis.com/auth/drive.metadata.readonly",
///     "expires_in":436
/// }
/// "#;
///
/// let expected = TokenInfo {
///     active: true,
///     user_id: Some(UserId::new("123456789")),
///     scope: vec![
///         Scope::new("https://www.googleapis.com/auth/drive.metadata.readonly"),
///     ],
///     expires_in_seconds: Some(436),
/// };
///
/// let token_info = GoogleV3TokenInfoParser.parse(sample).unwrap();
///
/// assert_eq!(expected, token_info);
/// ```
///
///
pub struct GoogleV3TokenInfoParser;

impl TokenInfoParser for GoogleV3TokenInfoParser {
    fn parse(&self, json: &[u8]) -> ::std::result::Result<TokenInfo, String> {
        parse(
            json,
            None,
            Some("user_id"),
            Some("scope"),
            Some("expires_in"),
        )
    }
}

/// Parses a `TokenInfo` from JSON
///
/// [Description](https://images-na.ssl-images-amazon.
/// com/images/G/01/lwa/dev/docs/website-developer-guide._TTH_.pdf)
///
/// ##Example
///
/// ```rust
/// use tokkit::*;
/// use tokkit::token_info::*;
/// use tokkit::token_info::parsers::AmazonTokenInfoParser;
///
/// let sample = br#"
/// {
///     "iss":"https://www.amazon.com",
///     "user_id": "amznl.account.K2LI23KL2LK2",
///     "aud": "amznl.oa2-client.ASFWDFBRN",
///     "app_id": "amznl.application.436457DFHDH",
///     "exp": 3597,
///     "iat": 1311280970
/// }
/// "#;
///
/// let expected = TokenInfo {
///     active: true,
///     user_id: Some(UserId::new("amznl.account.K2LI23KL2LK2")),
///     scope: Vec::new(),
///     expires_in_seconds: Some(3597),
/// };
///
/// let token_info = AmazonTokenInfoParser.parse(sample).unwrap();
///
/// assert_eq!(expected, token_info);
/// ```
pub struct AmazonTokenInfoParser;

impl TokenInfoParser for AmazonTokenInfoParser {
    fn parse(&self, json: &[u8]) -> ::std::result::Result<TokenInfo, String> {
        parse(json, None, Some("user_id"), Some("scope"), Some("exp"))
    }
}


pub fn parse(
    json: &[u8],
    active_field: Option<&str>,
    user_id_field: Option<&str>,
    scope_field: Option<&str>,
    expires_field: Option<&str>,
) -> ::std::result::Result<TokenInfo, String> {
    use json::*;
    let json = str::from_utf8(json).map_err(|err| err.to_string())?;
    let json = ::json::parse(json).map_err(|err| err.to_string())?;
    match json {
        JsonValue::Object(data) => {
            let active = if let Some(active_field) = active_field {
                match data.get(active_field) {
                    Some(&JsonValue::Boolean(active)) => active,
                    Some(&JsonValue::Short(s)) => {
                        s.parse().map_err(|err| ToString::to_string(&err))?
                    }
                    invalid => {
                        bail!(format!(
                            "Expected a boolean as the 'active' field in '{}' but found a {:?}",
                            active_field,
                            invalid
                        ))
                    }
                }
            } else {
                true
            };
            let user_id = if let Some(user_id_field) = user_id_field {
                match data.get(user_id_field) {
                    Some(&JsonValue::Short(ref user_id)) => Some(UserId::new(user_id.as_ref())),
                    Some(&JsonValue::String(ref user_id)) => Some(UserId::new(user_id.as_ref())),
                    invalid => {
                        bail!(format!(
                            "Expected a string as the user id in field '{}' but found a {:?}",
                            user_id_field,
                            invalid
                        ))
                    }
                }
            } else {
                None
            };
            let scope = if let Some(scope_field) = scope_field {
                match data.get(scope_field) {
                    Some(&JsonValue::Array(ref values)) => {
                        let mut scopes = Vec::with_capacity(values.len());
                        for elem in values {
                            match elem {
                                &JsonValue::String(ref v) => scopes.push(Scope(v.clone())),
                                &JsonValue::Short(ref v) => scopes.push(Scope::new(v.as_ref())),
                                invalid => {
                                    bail!(format!(
                                        "Expected a string as a scope in ['{}'] but found '{}'",
                                        scope_field,
                                        invalid
                                    ))
                                }
                            }
                        }
                        scopes
                    }
                    Some(&JsonValue::String(ref scope)) => split_scopes(scope.as_ref()),
                    Some(&JsonValue::Short(ref scope)) => split_scopes(scope.as_ref()),
                    None => Vec::new(),
                    invalid => {
                        bail!(format!(
                            "Expected an array or string for the \
                        scope(s) in field '{}' but found a {:?}",
                            scope_field,
                            invalid
                        ))
                    }
                }
            } else {
                Vec::new()
            };
            let expires_in = if let Some(expires_field) = expires_field {
                match data.get(expires_field) {
                    Some(&JsonValue::Number(number)) => {
                        let expires: f64 = number.into();
                        let expires = expires.round() as i64;
                        if expires >= 0 {
                            Some(expires as u64)
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
                    invalid => {
                        bail!(format!(
                            "Expected a number for field '{}' but found a {:?}",
                            expires_field,
                            invalid
                        ))
                    }
                }
            } else {
                None
            };
            Ok(TokenInfo {
                active: active,
                user_id: user_id,
                scope: scope,
                expires_in_seconds: expires_in,
            })
        }
        _ => Err(
            "Expected an object but found something else which i won't show\
                since it might contain a token."
                .to_string(),
        ),
    }
}

fn split_scopes(input: &str) -> Vec<Scope> {
    input
        .split(' ')
        .filter(|s| s.len() > 0)
        .map(Scope::new)
        .collect()
}

#[test]
fn google_v3_token_info_multiple_scopes() {
    let sample = br#"
    {
        "aud":"8819981768.apps.googleusercontent.com",
        "user_id":"123456789",
        "scope":"a b https://www.googleapis.com/auth/drive.metadata.readonly d",
        "expires_in":436
    }
    "#;

    let expected = TokenInfo {
        active: true,
        user_id: Some(UserId::new("123456789")),
        scope: vec![
            Scope::new("a"),
            Scope::new("b"),
            Scope::new("https://www.googleapis.com/auth/drive.metadata.readonly"),
            Scope::new("d"),
        ],
        expires_in_seconds: Some(436),
    };

    let token_info = GoogleV3TokenInfoParser.parse(sample).unwrap();

    assert_eq!(expected, token_info);
}

#[test]
fn google_v3_token_info_multiple_scopes_whitespaces() {
    let sample = br#"
    {
        "aud":"8819981768.apps.googleusercontent.com",
        "user_id":"123456789",
        "scope":" a     b  https://www.googleapis.com/auth/drive.metadata.readonly d   ",
        "expires_in":436
    }
    "#;

    let expected = TokenInfo {
        active: true,
        user_id: Some(UserId::new("123456789")),
        scope: vec![
            Scope::new("a"),
            Scope::new("b"),
            Scope::new("https://www.googleapis.com/auth/drive.metadata.readonly"),
            Scope::new("d"),
        ],
        expires_in_seconds: Some(436),
    };

    let token_info = GoogleV3TokenInfoParser.parse(sample).unwrap();

    assert_eq!(expected, token_info);
}
#[test]
fn amazon_token_info() {}
