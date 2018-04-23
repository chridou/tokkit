# tokkit

[![crates.io](https://img.shields.io/crates/v/tokkit.svg)](https://crates.io/crates/tokkit)
[![docs.rs](https://docs.rs/tokkit/badge.svg)](https://docs.rs/tokkit)
[![downloads](https://img.shields.io/crates/d/tokkit.svg)](https://crates.io/crates/tokkit)
[![build Status](https://travis-ci.org/chridou/tokkit.svg?branch=master)](https://travis-ci.
org/chridou/tokkit)
[![license-mit](http://img.shields.io/badge/license-MIT-blue.svg)](https://github.
com/chridou/tokkit/blob/master/LICENSE-MIT)
[![license-apache](http://img.shields.io/badge/license-APACHE-blue.svg)](https://github.
com/chridou/tokkit/blob/master/LICENSE-APACHE)

`tokkit` is a simple(even simplistic) **tok**en tool**kit** for OAUTH2 token
introspection

## Adding tokkit to your project

tokkit is available on [crates.io](https://crates.io/crates/tokkit).

## Documentation

The documentation is available [online](https://docs.rs/tokkit).

## Features

### Verify Access Tokens

`tokkit` contains a module `token_info` for protected resources to verify access tokens.

```rust
use tokkit::*;
use tokkit::client::*;

let builder = TokenInfoServiceClientBuilder::google_v3();

let service = builder.build().unwrap();

let token = AccessToken::new("<token>");

let tokeninfo = service.introspect(&token).unwrap();
```

## Recen changes

* 0.8.1
   * Added experimental supprt for saync clinet.

## License

tokkit is primarily distributed under the terms of
both the MIT license and the Apache License (Version 2.0).

Copyright (c) 2017 Christian Douven
Token verification for protected resources on resource servers.

See [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
and
[Roles](https://tools.ietf.org/html/rfc6749#section-1.1)

License: Apache-2.0/MIT
