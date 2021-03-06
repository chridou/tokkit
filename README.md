# tokkit

[![crates.io](https://img.shields.io/crates/v/tokkit.svg)](https://crates.io/crates/tokkit)
[![docs.rs](https://docs.rs/tokkit/badge.svg)](https://docs.rs/tokkit)
[![downloads](https://img.shields.io/crates/d/tokkit.svg)](https://crates.io/crates/tokkit)
[![build Status](https://travis-ci.org/chridou/tokkit.svg?branch=master)](https://travis-ci.org/chridou/tokkit)
[![license-mit](http://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/chridou/tokkit/blob/master/LICENSE-MIT)
[![license-apache](http://img.shields.io/badge/license-APACHE-blue.svg)](https://github.com/chridou/tokkit/blob/master/LICENSE-APACHE)

`tokkit` is a simple(even simplistic) **tok**en tool**kit** for OAUTH2 token
introspection

## Adding tokkit to your project

tokkit is available on [crates.io](https://crates.io/crates/tokkit).

## Documentation

The documentation is available [online](https://docs.rs/tokkit).

## Features

* `async`: Adds a `reqwest` based async client.
See also `TokenInfoServiceClientBuilder`
* `metrix`: Add support for the [metrix](https://crates.io/crates/metrix)
crate(async client only)
See also `TokenInfoServiceClientBuilder`

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

## Recent changes

* 0.16.0
   * Upgraded `metrix` feature to `0.10` (breaking change in `metrix`)
* 0.15.3
   * Use reqwest 0.9
* 0.15.2
   * Async Client has default https connector
* 0.15.1
   * Async Client can be created with a given Executor
* 0.15.0
   * updated metrix
* 0.14.0
   * Add a client that takes an HttpClient as a parameter
* 0.13.0
   * parser does not need the http client in an Arc* 0.12.1

## License

tokkit is primarily distributed under the terms of
both the MIT license and the Apache License (Version 2.0).

Copyright (c) 2017 Christian Douven
Token verification for protected resources on resource servers.

See [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
and
[Roles](https://tools.ietf.org/html/rfc6749#section-1.1)

License: Apache-2.0/MIT
