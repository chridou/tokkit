use std::fmt;

pub struct Token(pub String);

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct Scope(pub String);

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}