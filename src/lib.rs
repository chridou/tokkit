#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;

extern crate json;
extern crate reqwest;

mod shared;
pub use shared::*;

pub mod client {}

pub mod token_info;
