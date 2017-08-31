error_chain! {
    types {
        Error, ErrorKind, ResultExt, Result;
    }

    errors {
        NoToken(t: String) {
            description("no token")
            display("no token: '{}'", t)
        }
        NotInitialized(t: String) {
            description("token not initialized")
            display("Token not initialized: '{}'", t)
        }
        TokenService(error: ::client::tokenservice::TokenServiceError) {
            description("error from tokenservice")
            display("Error from tokenservice: \"{}\"", error)
        }
    }
}

impl Clone for ErrorKind {
    fn clone(&self) -> Self {
        match *self {
            ErrorKind::NoToken(ref t) => ErrorKind::NoToken(t.clone()),
            ErrorKind::NotInitialized(ref t) => ErrorKind::NotInitialized(t.clone()),
            ErrorKind::TokenService(ref err) => ErrorKind::TokenService(err.clone()),
            ErrorKind::Msg(ref m) => ErrorKind::Msg(m.clone()),
        }
    }
}
