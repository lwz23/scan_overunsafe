// Copyright 2012-2014 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// run-pass
#![allow(non_camel_case_types)]

// aux-build:anon_trait_static_method_lib.rs

extern crate anon_trait_static_method_lib;
use anon_trait_static_method_lib::Foo;

pub fn main() {
    let x = Foo::new();
    println!("{}", x.x);
}
