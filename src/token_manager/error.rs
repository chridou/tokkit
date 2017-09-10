error_chain! {
    types {
        Error, ErrorKind, ResultExt, Result;
    }

    errors {
        /// There is no token with that identifier...
        NoToken(t: String) {
            description("no token")
            display("no token: '{}'", t)
        }
        /// The token with the given identifier is not yet initialized
        NotInitialized(t: String) {
            description("token not initialized")
            display("Token not initialized: '{}'", t)
        }
        /// An error from the `AccessTokenProvider`
        AccessTokenProvider(error: ::token_manager::token_provider::AccessTokenProviderError) {
            description("error from token provider")
            display("Error from token provider: \"{}\"", error)
        }
    }
}

impl Clone for ErrorKind {
    fn clone(&self) -> Self {
        match *self {
            ErrorKind::NoToken(ref t) => ErrorKind::NoToken(t.clone()),
            ErrorKind::NotInitialized(ref t) => ErrorKind::NotInitialized(t.clone()),
            ErrorKind::AccessTokenProvider(ref err) => ErrorKind::AccessTokenProvider(err.clone()),
            ErrorKind::Msg(ref m) => ErrorKind::Msg(m.clone()),
        }
    }
}
