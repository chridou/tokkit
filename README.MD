# tokkit

WORK IN PROGRESS

`tokkit` is a simple **tok**en tool**kit** for OAUTH2 authorization.

## Documentation

The documentation is available [online](https://docs.rs/tokkit).

## Verify Access Tokens

`tokkit` contains a module `token_info` for protected resources to verify access 
tokens via a token introspection service.

```rust,no_run
use tokkit::*;
use tokkit::token_info::*;
let builder = RemoteTokenInfoServiceBuilder::google_v3();
let service = builder.build().unwrap();

let token = AccessToken::new("<token>");
 
let tokeninfo = service.get_token_info(&token).unwrap();
```

## Managing Tokens

To be done....

## License

tokkit is primarily distributed under the terms of 
both the MIT license and the Apache License (Version 2.0).
Copyright (c) 2017 Christian Douven
