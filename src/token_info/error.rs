error_chain! {
    types {
        Error, ErrorKind, ResultExt, Result;
    }

    errors {
        InvalidResponseContent(t: String) {
            description("invalid response content")
            display("Invalid response content: '{}'", t)
        }
        UrlError(t: String) {
            description("invalid url")
            display("Invalid url: '{}'", t)
        }
        NotAuthenticated(t: String) {
            description("not authenticated")
            display("Not authenticated: '{}'", t)
        }
        Connection(t: String) {
            description("connection error")
            display("Connection error: '{}'", t)
        }
        IoError(t: String) {
            description("io error")
            display("IO error: '{}'", t)
        }
        ClientError(status: String, t: String) {
            description("client error")
            display("Client error({}: '{}'", status, t)
        }
        ServerError(status: String, t: String) {
            description("server error")
            display("Server error({}): '{}'", status, t)
        }
    }
}

impl From<::std::io::Error> for Error {
    fn from(what: ::std::io::Error) -> Error {
        ErrorKind::IoError(format!("{}", what)).into()
    }
}
