error_chain! {
    types {
        Error, ErrorKind, ResultExt, Result;
    }

    errors {
        InvalidResponseContent(t: String) {
            description("invalid response content")
            display("Invalid response content: '{}'", t)
        }
    }
}