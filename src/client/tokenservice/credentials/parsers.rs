use std::str;
use json;
use json::*;

use super::*;

pub fn parse_client_credentials(
    bytes: &[u8],
    client_id_field_name: &str,
    client_secret_field_name: &str,
) -> CredentialsResult<ClientCredentials> {
    parse_credentials(bytes, client_id_field_name, client_secret_field_name)
        .map(|(client_id, client_secret)| {
            ClientCredentials {
                client_id,
                client_secret,
            }
        })
}

pub fn parse_user_credentials(
    bytes: &[u8],
    user_id_field_name: &str,
    user_password_field_name: &str,
) -> CredentialsResult<UserCredentials> {
    parse_credentials(bytes, user_id_field_name, user_password_field_name)
        .map(|(username, password)| {
            UserCredentials { username, password }
        })
}

fn parse_credentials(
    bytes: &[u8],
    id_field_name: &str,
    secret_field_name: &str,
) -> CredentialsResult<(String, String)> {
    let json_utf8 = str::from_utf8(bytes).map_err(|err| {
        CredentialsError::Parse(err.to_string())
    })?;
    let json = json::parse(json_utf8).map_err(|err| {
        CredentialsError::Parse(err.to_string())
    })?;

    if let JsonValue::Object(data) = json {
        let id = match data.get(id_field_name) {
            Some(&JsonValue::Short(user_id)) => user_id.to_string(),
            Some(&JsonValue::String(ref user_id)) => user_id.clone(),
            invalid => {
                bail!(CredentialsError::Parse(format!(
                    "Expected a string as the user id in field '{}' but found a {:?}",
                    id_field_name,
                    invalid
                )))
            }
        };

        let secret = match data.get(secret_field_name) {
            Some(&JsonValue::Short(secret)) => secret.to_string(),
            Some(&JsonValue::String(ref secret)) => secret.clone(),
            invalid => {
                bail!(CredentialsError::Parse(format!(
                    "Expected a string as the secret in field '{}' but found a {:?}",
                    secret_field_name,
                    invalid
                )))
            }
        };
        Ok((id, secret))
    } else {
        bail!(CredentialsError::Parse("Not a JSON object".to_string()))
    }
}
