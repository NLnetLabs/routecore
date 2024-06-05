#![no_main]

use std::cmp::Ordering::*;
use std::fmt::Debug;
use libfuzzer_sys::fuzz_target;
use routecore::bgp::{
    path_attributes::PaMap,
    path_selection::{OrdStrat, OrdRoute, Rfc4271, SkipMed, TiebreakerInfo,
        best_backup, best
    }
};

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

fn verify_path_selection<'a, T, OS, I>(candidates: I)
    where
        I: Clone + Iterator<Item = T>,
        T: Debug + Ord + core::borrow::Borrow<OrdRoute<'a, OS>>,
        OS: Debug + OrdStrat,
{
    let best1 = best(candidates.clone()).unwrap();
    let (best2, backup2) = best_backup(candidates.clone());
    let best2 = best2.unwrap();

    assert_eq!(best1.borrow(), best2.borrow());
    assert_eq!(best1.borrow().pa_map(), best2.borrow().pa_map());
    assert_eq!(best1.borrow().tiebreakers(), best2.borrow().tiebreakers());

    let backup2 = match backup2 {
        Some(route) => route,
        None => {
            let mut iter = candidates.clone();
            let mut cur  = iter.next().unwrap();
            for c in iter {
                assert_eq!(cur.borrow().inner(), c.borrow().inner());
                cur = c;
            }
            return;
        }
    };

    assert_ne!(
        (best2.borrow().tiebreakers(), best2.borrow().pa_map()),
        (backup2.borrow().tiebreakers(), backup2.borrow().pa_map()),
    );
}

// XXX while doing fuzz_target!(|data: &[u8]| ... and then creating an
// Unstructured from `data` can be useful, the Debug output becomes quite
// useless. It'll be just a bunch of bytes without any structure.
// So, something like
//      fuzz_target!(|data: (OrdRoute, OrdRoute, OrdRoute)| {
//  has benefits.
//

fuzz_target!(|data: (
        PaMap, TiebreakerInfo,
        PaMap, TiebreakerInfo,
        PaMap, TiebreakerInfo
    )|{

    //dbg!(&data);

    let a = match OrdRoute::<SkipMed>::try_new(&data.0, data.1) {
        Ok(r) => r,
        Err(_) => return,
    };
    let b = match OrdRoute::<SkipMed>::try_new(&data.2, data.3) {
        Ok(r) => r,
        Err(_) => return,
    };
    let c = match OrdRoute::<SkipMed>::try_new(&data.4, data.5) {
        Ok(r) => r,
        Err(_) => return,
    };

    //dbg!("skipmed");
    verify_ord(&a, &b, &c);
    verify_path_selection([&a, &b, &c, &b, &c, &a].into_iter());

    //dbg!("rfc4271");
    /*
    verify_ord(
        &a.into_strat::<Rfc4271>(),
        &b.into_strat::<Rfc4271>(),
        &c.into_strat::<Rfc4271>()
    );
    */

});
