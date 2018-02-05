//! Parser for credentials, mostl likely JSON
use std::str;
use json;
use json::*;

use super::*;

/// A parser for `ClientCredentials`
pub trait ClientCredentialsParser {
    fn parse(&self, bytes: &[u8]) -> CredentialsResult<ClientCredentials>;
}

/// The default parser for `ClientCredentials`.
///
/// It parses the following JSON:
///
/// ```javascript
/// {
///    "client_id" : "<id>",
///    "client_secret" : "<secret>"
/// }
/// ```
pub struct DefaultClientCredentialsParser;

impl ClientCredentialsParser for DefaultClientCredentialsParser {
    fn parse(&self, bytes: &[u8]) -> CredentialsResult<ClientCredentials> {
        parse_client_credentials(bytes, "client_id", "client_secret")
    }
}

/// A parser for `ResourceOwnerCredentials`
pub trait ResourceOwnerCredentialsParser {
    fn parse(&self, bytes: &[u8]) -> CredentialsResult<ResourceOwnerCredentials>;
}

/// The default parser for `ResourceOwnerCredentials`.
///
/// It parses the following JSON:
///
/// ```javascript
/// {
///    "username" : "<id>",
///    "password" : "<secret>"
/// }
/// ```
pub struct DefaultResourceOwnerCredentialsParser;

impl ResourceOwnerCredentialsParser for DefaultResourceOwnerCredentialsParser {
    fn parse(&self, bytes: &[u8]) -> CredentialsResult<ResourceOwnerCredentials> {
        parse_resource_owner_credentials(bytes, "username", "password")
    }
}

/// A parser `ResourceOwnerCredentials`where the resource owner is an application.
///
/// It parses the following JSON:
///
/// ```javascript
/// {
///    "application_username" : "<id>",
///    "application_password" : "<secret>"
/// }
/// ```
pub struct ApplicationResourceOwnerCredentialsParser;

impl ResourceOwnerCredentialsParser for ApplicationResourceOwnerCredentialsParser {
    fn parse(&self, bytes: &[u8]) -> CredentialsResult<ResourceOwnerCredentials> {
        parse_resource_owner_credentials(bytes, "application_username", "application_password")
    }
}

pub fn parse_client_credentials(
    bytes: &[u8],
    client_id_field_name: &str,
    client_secret_field_name: &str,
) -> CredentialsResult<ClientCredentials> {
    parse_credentials(bytes, client_id_field_name, client_secret_field_name).map(
        |(client_id, client_secret)| ClientCredentials {
            client_id,
            client_secret,
        },
    )
}

pub fn parse_resource_owner_credentials(
    bytes: &[u8],
    user_id_field_name: &str,
    user_password_field_name: &str,
) -> CredentialsResult<ResourceOwnerCredentials> {
    parse_credentials(bytes, user_id_field_name, user_password_field_name)
        .map(|(username, password)| ResourceOwnerCredentials { username, password })
}

fn parse_credentials(
    bytes: &[u8],
    id_field_name: &str,
    secret_field_name: &str,
) -> CredentialsResult<(String, String)> {
    let json_utf8 = str::from_utf8(bytes).map_err(|err| CredentialsError::Parse(err.to_string()))?;
    let json = json::parse(json_utf8).map_err(|err| CredentialsError::Parse(err.to_string()))?;

    if let JsonValue::Object(data) = json {
        let id = match data.get(id_field_name) {
            Some(&JsonValue::Short(user_id)) => user_id.to_string(),
            Some(&JsonValue::String(ref user_id)) => user_id.clone(),
            invalid => bail!(CredentialsError::Parse(format!(
                "Expected a string as the user id in field '{}' but found a {:?}",
                id_field_name, invalid
            ))),
        };

        let secret = match data.get(secret_field_name) {
            Some(&JsonValue::Short(secret)) => secret.to_string(),
            Some(&JsonValue::String(ref secret)) => secret.clone(),
            invalid => bail!(CredentialsError::Parse(format!(
                "Expected a string as the secret in field '{}' but found a {:?}",
                secret_field_name, invalid
            ))),
        };
        Ok((id, secret))
    } else {
        bail!(CredentialsError::Parse("Not a JSON object".to_string()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn default_client_credentials_parser() {
        let sample = r#"
        {
            "client_id" : "<id>",
            "client_secret" : "<secret>"
        }
        "#;

        let res = DefaultClientCredentialsParser
            .parse(sample.as_bytes())
            .unwrap();
        assert_eq!("<id>", res.client_id);
        assert_eq!("<secret>", res.client_secret);
    }

    #[test]
    fn user_credentials_parser() {
        let sample = r#"
        {
            "username" : "<id>",
            "password" : "<secret>"
        }
        "#;

        let res = DefaultResourceOwnerCredentialsParser
            .parse(sample.as_bytes())
            .unwrap();
        assert_eq!("<id>", res.username);
        assert_eq!("<secret>", res.password);
    }

    #[test]
    fn application_user_credentials_parser() {
        let sample = r#"
        {
            "application_username" : "<id>",
            "application_password" : "<secret>"
        }
        "#;

        let res = ApplicationResourceOwnerCredentialsParser
            .parse(sample.as_bytes())
            .unwrap();
        assert_eq!("<id>", res.username);
        assert_eq!("<secret>", res.password);
    }
}
