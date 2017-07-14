use super::*;
use std::str;

/// Parses a `TokenInfo` from JSON
///
/// [Description](http://planb.readthedocs.io/en/latest/intro.html#token-info)
///
/// ##Example
///
/// ```javascript
/// {
/// "access_token": "token-base64",
/// "id_token": "token-base64",
/// "token_type": "Bearer",
/// "expires_in": 28800,
/// "scope": "cn",
/// "realm": "/services"
/// }
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
/// ```javascript
/// {
///   "aud":"8819981768.apps.googleusercontent.com",
///   "user_id":"123456789",
///   "scope":"https://www.googleapis.com/auth/drive.metadata.readonly",
///   "expires_in":436
/// }
/// ```
pub struct GoogleTokenInfoParser;

impl TokenInfoParser for GoogleTokenInfoParser {
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
/// ```javascript
/// {
///     "iss":"https://www.amazon.com",
///     "user_id": "amznl.account.K2LI23KL2LK2",
///     "aud": "amznl.oa2-client.ASFWDFBRN",
///     "app_id": "amznl.application.436457DFHDH",
///     "exp": 3597,
///     "iat": l3ll280970,
/// }
/// ```
pub struct AmazonTokenInfoParser;

impl TokenInfoParser for AmazonTokenInfoParser {
    fn parse(&self, json: &[u8]) -> ::std::result::Result<TokenInfo, String> {
        parse(json, "user_id", "scope", "exp")
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
fn parse_plan_b_token_info() {
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
        }
        "#;

    let expected = TokenInfo {
        user_id: Some(UserId::new("test2")),
        scopes: vec![Scope::new("cn")],
        expires_in_seconds: 28292,
    };

    let token_info = PlanBTokenInfoParser.parse(sample).unwrap();

    assert_eq!(expected, token_info);
}

#[test]
fn google_token_info() {
    let sample = br#"
    {
        "aud":"8819981768.apps.googleusercontent.com",
        "user_id":"123456789",
        "scope":"https://www.googleapis.com/auth/drive.metadata.readonly",
        "expires_in":436
    }
    "#;

    let expected = TokenInfo {
        user_id: Some(UserId::new("123456789")),
        scopes: vec![
            Scope::new("https://www.googleapis.com/auth/drive.metadata.readonly"),
        ],
        expires_in_seconds: 436,
    };

    let token_info = GoogleTokenInfoParser.parse(sample).unwrap();

    assert_eq!(expected, token_info);
}

#[test]
fn google_token_info_multiple_scopes() {
    let sample = br#"
    {
        "aud":"8819981768.apps.googleusercontent.com",
        "user_id":"123456789",
        "scope":"a b https://www.googleapis.com/auth/drive.metadata.readonly d",
        "expires_in":436
    }
    "#;

    let expected = TokenInfo {
        user_id: Some(UserId::new("123456789")),
        scopes: vec![
            Scope::new("a"),
            Scope::new("b"),
            Scope::new("https://www.googleapis.com/auth/drive.metadata.readonly"),
            Scope::new("d"),
        ],
        expires_in_seconds: 436,
    };

    let token_info = GoogleTokenInfoParser.parse(sample).unwrap();

    assert_eq!(expected, token_info);
}

#[test]
fn google_token_info_multiple_scopes_2_whitespace() {
    let sample = br#"
    {
        "aud":"8819981768.apps.googleusercontent.com",
        "user_id":"123456789",
        "scope":"a b  https://www.googleapis.com/auth/drive.metadata.readonly d",
        "expires_in":436
    }
    "#;

    let expected = TokenInfo {
        user_id: Some(UserId::new("123456789")),
        scopes: vec![
            Scope::new("a"),
            Scope::new("b"),
            Scope::new("https://www.googleapis.com/auth/drive.metadata.readonly"),
            Scope::new("d"),
        ],
        expires_in_seconds: 436,
    };

    let token_info = GoogleTokenInfoParser.parse(sample).unwrap();

    assert_eq!(expected, token_info);
}
#[test]
fn amazon_token_info() {
    let sample = br#"
    {
        "iss":"https://www.amazon.com",
        "user_id": "amznl.account.K2LI23KL2LK2",
        "aud": "amznl.oa2-client.ASFWDFBRN",
        "app_id": "amznl.application.436457DFHDH",
        "exp": 3597,
        "iat": "l3ll280970"
    }
    "#;

    let expected = TokenInfo {
        user_id: Some(UserId::new("amznl.account.K2LI23KL2LK2")),
        scopes: Vec::new(),
        expires_in_seconds: 3597,
    };

    let token_info = AmazonTokenInfoParser.parse(sample).unwrap();

    assert_eq!(expected, token_info);
}
