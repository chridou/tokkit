#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;

extern crate json;
extern crate reqwest;

pub mod client {}

pub mod resource_server;
pub(crate) mod shared;
