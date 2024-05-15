#![no_main]

use std::cmp::Ordering::*;
use libfuzzer_sys::fuzz_target;
use routecore::bgp::{path_attributes::PaMap, path_selection::{OrdRoute, Rfc4271, SkipMed, TiebreakerInfo}};

fn verify_ord<T>(a: &T, b: &T, c: &T)
    where T: Ord
{
    match (a.cmp(b), b.cmp(c)) {
        // a < b < c
        (Less, Less) => assert_eq!(a.cmp(c), Less),
        // a < b == c
        (Less, Equal) => assert_eq!(a.cmp(c), Less),
        // a < b > c
        (Less, Greater) => { } ,

        // a == b == c
        (Equal, Equal) => {
            assert_eq!(a.cmp(c), Equal);
            // Test PartialEq
            assert!(a == b);
            assert!(b == c);
        }
        // a == b < c
        (Equal, Less) => assert_eq!(a.cmp(c), Less),
        // a == b > c
        (Equal, Greater) => assert_eq!(a.cmp(c), Greater),

        // a > b > c
        (Greater, Greater) => assert_eq!(a.cmp(c), Greater),
        // a > b < c
        (Greater, Less) => { },
        // a > b == c
        (Greater, Equal) => assert_eq!(a.cmp(c), Greater),
    }
}

// XXX while doing fuzz_target!(|data: &[u8]| ... and then creating an
// Unstructured from `data` can be useful, the Debug output becomes quite
// useless. It'll be just a bunch of bytes without any structure.
// So, something like
//      fuzz_target!(|data: (OrdRoute, OrdRoute, OrdRoute)| {
//  has benefits.
//

//fuzz_target!(|data: &[u8]| {
fuzz_target!(|data: (PaMap, TiebreakerInfo, PaMap, TiebreakerInfo, PaMap, TiebreakerInfo)| {

    //dbg!(&data);

    let a = match OrdRoute::<()>::try_new(&data.0, data.1) {
        Ok(r) => r,
        Err(_) => return,
    };
    let b = match OrdRoute::<()>::try_new(&data.2, data.3) {
        Ok(r) => r,
        Err(_) => return,
    };
    let c = match OrdRoute::<()>::try_new(&data.4, data.5) {
        Ok(r) => r,
        Err(_) => return,
    };

    verify_ord(
        &OrdRoute::<SkipMed>::from(a),
        &OrdRoute::<SkipMed>::from(b),
        &OrdRoute::<SkipMed>::from(c),
    );

    //verify_ord(
    //    &OrdRoute::<Rfc4271>::from(a),
    //    &OrdRoute::<Rfc4271>::from(b),
    //    &OrdRoute::<Rfc4271>::from(c),
    //);
});
