# tokkit

`tokkit` is a simple(even simplistic) **tok**en tool**kit** for OAUTH2 authorization
targetting service to service authorization.

## Adding tokkit to your project

tokkit is available on [crates.io](https://crates.io/crates/tokkit).

## Documentation

The documentation is available [online](https://docs.rs/tokkit).

## Features

### Verify Access Tokens

`tokkit` contains a module `token_info` for protected resources to verify access tokens.

```rust,no_run
use tokkit::*;
use tokkit::token_info::*;
let builder = RemoteTokenInfoServiceBuilder::google_v3();
let service = builder.build().unwrap();
let token = AccessToken::new("<token>");
let tokeninfo = service.introspect(&token).unwrap();
```

### Managing Tokens

`tokkit` can manage and automatically update your access tokens if you
are a client and want to access a resource owners resources.

Currently `tokkit` only supports the
[Resource Owner Password Credentials Grant](https://tools.ietf.org/html/rfc6749#section-4.3)
which should only be used if the resource owner can really trust the client.

```rust,no_run
use tokkit::*;
use tokkit::token_manager::*;
use tokkit::token_manager::token_provider::*;
use tokkit::token_manager::token_provider::credentials::*;

let credentials_provider = SplitFileCredentialsProvider::with_default_parsers_from_env()
    .unwrap();

let token_provider =
    ResourceOwnerPasswordCredentialsGrantProvider
        ::from_env_with_credentials_provider(credentials_provider)
        .unwrap();

let token_group =
    ManagedTokenGroupBuilder::single_token(
        "my_token_identifier", 
        vec![Scope::new("read_my_diary")], 
        token_provider)
    .build()
    .unwrap();

let token_source = AccessTokenManager::start(vec![token_group]).unwrap();

let access_token = token_source.get_access_token(&"my_token_identifier").unwrap();
```

## License

tokkit is primarily distributed under the terms of
both the MIT license and the Apache License (Version 2.0).
Copyright (c) 2017 Christian Douven