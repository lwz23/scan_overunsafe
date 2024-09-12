// Copyright 2017 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// compile-flags: -Z parse-only -Z continue-parse-after-error

fn f() -> impl A + {} // OK
fn f() -> impl A + B {} // OK
fn f() -> dyn A + B {} // OK
fn f() -> A + B {} // OK

impl S {
    fn f(self) -> impl A + { // OK
        let _ = |a, b| -> impl A + {}; // OK
    }
    fn f(self) -> impl A + B { // OK
        let _ = |a, b| -> impl A + B {}; // OK
    }
    fn f(self) -> dyn A + B { // OK
        let _ = |a, b| -> dyn A + B {}; // OK
    }
    fn f(self) -> A + B { // OK
        let _ = |a, b| -> A + B {}; // OK
    }
}

type A = fn() -> impl A +;
//~^ ERROR ambiguous `+` in a type
type A = fn() -> impl A + B;
//~^ ERROR ambiguous `+` in a type
type A = fn() -> dyn A + B;
//~^ ERROR ambiguous `+` in a type
type A = fn() -> A + B;
//~^ ERROR expected a path on the left-hand side of `+`, not `fn() -> A`

type A = Fn() -> impl A +;
//~^ ERROR ambiguous `+` in a type
type A = Fn() -> impl A + B;
//~^ ERROR ambiguous `+` in a type
type A = Fn() -> dyn A + B;
//~^ ERROR ambiguous `+` in a type
type A = Fn() -> A + B; // OK, interpreted as `(Fn() -> A) + B` for compatibility

type A = &impl A +;
//~^ ERROR ambiguous `+` in a type
type A = &impl A + B;
//~^ ERROR ambiguous `+` in a type
type A = &dyn A + B;
//~^ ERROR ambiguous `+` in a type
type A = &A + B;
//~^ ERROR expected a path on the left-hand side of `+`, not `&A`

fn main() {}
