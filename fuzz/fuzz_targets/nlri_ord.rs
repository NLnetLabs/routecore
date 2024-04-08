#![no_main]

use std::cmp::Ordering::*;
use libfuzzer_sys::fuzz_target;
use routecore::bgp::nlri::afisafi::Nlri;

fuzz_target!(|data: (Nlri<&[u8]>, Nlri<&[u8]>, Nlri<&[u8]>)| {
    let (a, b, c) = data;
    match (a.cmp(&b), b.cmp(&c)) {
        // a < b < c
        (Less, Less) => assert_eq!(a.cmp(&c), Less),
        // a < b == c
        (Less, Equal) => assert_eq!(a.cmp(&c), Less),
        // a < b > c
        (Less, Greater) => { } ,

        // a == b == c
        (Equal, Equal) => assert_eq!(a.cmp(&c), Equal),
        // a == b < c
        (Equal, Less) => assert_eq!(a.cmp(&c), Less),
        // a == b > c
        (Equal, Greater) => assert_eq!(a.cmp(&c), Greater),

        // a > b > c
        (Greater, Greater) => assert_eq!(a.cmp(&c), Greater),
        // a > b < c
        (Greater, Less) => { },
        // a > b == c
        (Greater, Equal) => assert_eq!(a.cmp(&c), Greater),
    }
});

