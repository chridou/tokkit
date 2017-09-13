error_chain! {
    types {
        Error, ErrorKind, ResultExt, Result;
    }

    errors {
        /// The response from the introspection service was not valid.
        /// Most probably it was not pasable.
        InvalidResponseContent(t: String) {
            description("invalid response content")
            display("Invalid response content: '{}'", t)
        }
        /// The URL to the introspection service was invalid
        UrlError(t: String) {
            description("invalid url")
            display("Invalid url: '{}'", t)
        }
        /// The introspection service refused to process our request
        NotAuthenticated(t: String) {
            description("not authenticated")
            display("Not authenticated: '{}'", t)
        }
        /// The connection itself broke.
        Connection(t: String) {
            description("connection error")
            display("Connection error: '{}'", t)
        }
        /// There was an error reading data
        IoError(t: String) {
            description("io error")
            display("IO error: '{}'", t)
        }
        /// Our request to the introspection service was
        /// faulty
        ClientError(status: String, t: String) {
            description("client error")
            display("Client error({}: '{}'", status, t)
        }
        /// The intrespection service intself had an error
        ServerError(status: String, t: String) {
            description("server error")
            display("Server error({}): '{}'", status, t)
        }
        Other(t: String) {
            description("other error")
            display("Other eror error: '{}'", t)
        }
    }
}

impl From<::std::io::Error> for Error {
    fn from(what: ::std::io::Error) -> Error {
        ErrorKind::IoError(format!("{}", what)).into()
    }
}
