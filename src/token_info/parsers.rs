//! Various parsers for the responses of a token info service.
use super::*;
use std::str;
use std::env;

/// A configurable `TokenInfoParser`
pub struct CustomTokenInfoParser {
    user_id_field: String,
    scopes_field: String,
    expires_in_field: String,
}

impl CustomTokenInfoParser {
    pub fn new<U, S, E>(user_id_field: U, scopes_field: S, expires_in_field: E) -> Self
    where
        U: Into<String>,
        S: Into<String>,
        E: Into<String>,
    {
        CustomTokenInfoParser {
            user_id_field: user_id_field.into(),
            scopes_field: scopes_field.into(),
            expires_in_field: expires_in_field.into(),
        }
    }

    /// Create a new parser from environment variables.
    ///
    /// The following variables used to identify the field in a token info response:
    ///
    /// * `TOKKIT_TOKEN_INFO_PARSER_USER_ID_FIELD`(mandatory): The field name for the user id
    /// * `TOKKIT_TOKEN_INFO_PARSER_SCOPES_FIELD`(mandatory): The field name for scopes
    /// * `TOKKIT_TOKEN_INFO_PARSER_EXPIRES_IN_FIELD`(mandatory): The field name for the
    /// expiration
    pub fn from_env() -> InitializationResult<CustomTokenInfoParser> {
        let user_id_field = env::var("TOKKIT_TOKEN_INFO_PARSER_USER_ID_FIELD").map_err(
            |err| {
                InitializationError(format!("'TOKKIT_TOKEN_INFO_PARSER_USER_ID_FIELD': {}", err))
            },
        )?;
        let scopes_field = env::var("TOKKIT_TOKEN_INFO_PARSER_SCOPES_FIELD").map_err(
            |err| {
                InitializationError(format!("'TOKKIT_TOKEN_INFO_PARSER_SCOPES_FIELD': {}", err))
            },
        )?;
        let expires_in_field = env::var("TOKKIT_TOKEN_INFO_PARSER_EXPIRES_IN_FIELD")
            .map_err(|err| {
                InitializationError(format!(
                    "'TOKKIT_TOKEN_INFO_PARSER_EXPIRES_IN_FIELD': {}",
                    err
                ))
            })?;
        Ok(Self::new(user_id_field, scopes_field, expires_in_field))
    }
}

impl TokenInfoParser for CustomTokenInfoParser {
    fn parse(&self, json: &[u8]) -> ::std::result::Result<TokenInfo, String> {
        parse(
            json,
            &self.user_id_field,
            &self.scopes_field,
            &self.expires_in_field,
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
///     user_id: UserId::new("test2"),
///     scopes: vec![Scope::new("cn")],
///     expires_in_seconds: 28292,
/// };
///
/// let token_info = PlanBTokenInfoParser.parse(sample).unwrap();
///
/// assert_eq!(expected, token_info);
/// ```
pub struct PlanBTokenInfoParser;

impl TokenInfoParser for PlanBTokenInfoParser {
    fn parse(&self, json: &[u8]) -> ::std::result::Result<TokenInfo, String> {
        parse(json, "uid", "scope", "expires_in")
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
///     user_id: UserId::new("123456789"),
///     scopes: vec![
///         Scope::new("https://www.googleapis.com/auth/drive.metadata.readonly"),
///     ],
///     expires_in_seconds: 436,
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
        parse(json, "user_id", "scope", "expires_in")
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
///     user_id: UserId::new("amznl.account.K2LI23KL2LK2"),
///     scopes: Vec::new(),
///     expires_in_seconds: 3597,
/// };
///
/// let token_info = AmazonTokenInfoParser.parse(sample).unwrap();
///
/// assert_eq!(expected, token_info);
/// ```
pub struct AmazonTokenInfoParser;

impl TokenInfoParser for AmazonTokenInfoParser {
    fn parse(&self, json: &[u8]) -> ::std::result::Result<TokenInfo, String> {
        parse(json, "user_id", "scope", "exp")
    }
}


pub fn parse(
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
                Some(&JsonValue::String(ref user_id)) => UserId::new(user_id.as_ref()),
                Some(&JsonValue::Short(ref user_id)) => UserId::new(user_id.as_ref()),
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
                Some(&JsonValue::String(ref scope)) => split_scopes(scope.as_ref()),
                Some(&JsonValue::Short(ref scope)) => split_scopes(scope.as_ref()),
                None => Vec::new(),
                invalid => {
                    bail!(format!(
                        "Expected an array or string for the \
                        scope(s) in field '{}' but found a {:?}",
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
                invalid => {
                    bail!(format!(
                        "Expected a number for field '{}' but found a {:?}",
                        expires_field,
                        invalid
                    ))
                }
            };
            Ok(TokenInfo {
                user_id: user_id,
                scopes: scopes,
                expires_in_seconds: expires_in,
            })
        }
        Ok(_) => Err(
            "Expected an object but found something else which i won't show\
                since it might contain a token."
                .to_string(),
        ),
        Err(err) => Err(err.to_string()),
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
        user_id: UserId::new("123456789"),
        scopes: vec![
            Scope::new("a"),
            Scope::new("b"),
            Scope::new("https://www.googleapis.com/auth/drive.metadata.readonly"),
            Scope::new("d"),
        ],
        expires_in_seconds: 436,
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
        user_id: UserId::new("123456789"),
        scopes: vec![
            Scope::new("a"),
            Scope::new("b"),
            Scope::new("https://www.googleapis.com/auth/drive.metadata.readonly"),
            Scope::new("d"),
        ],
        expires_in_seconds: 436,
    };

    let token_info = GoogleV3TokenInfoParser.parse(sample).unwrap();

    assert_eq!(expected, token_info);
}
#[test]
fn amazon_token_info() {}
