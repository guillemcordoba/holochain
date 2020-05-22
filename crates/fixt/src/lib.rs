pub mod bool;
pub mod bytes;
pub mod number;
pub mod prelude;
pub mod serialized_bytes;
pub mod string;
pub mod unit;
pub use paste;

#[derive(Clone)]
/// the Fixturator is the struct that we wrap in our FooFixturator newtypes to impl Iterator over
/// each combination of Item and Curve needs its own Iterator implementation for Fixturator
/// Item is the Foo type of FooFixturator, i.e. the type of thing we are generating examples of
/// Curve represents some algorithm capable of generating fixtures
/// the Item is PhantomData because it simply represents a type to output
/// the Curve must be provided when the Fixturator is constructed to allow for paramaterized curves
/// this is most easily handled in most cases with the fixturator! and newtype_fixturator! macros
///
/// The inner index is always a single usize.
/// It can be ignored, e.g. in the case of Unpredictable implementations based on `rand::random()`.
/// If it is used it should be incremented by 1 and/or wrapped back to 0 to derive returned values.
/// Ideally the Curve should allow for efficient calculation of a fixture from any given index,
/// e.g. a fibbonacci curve would be a bad idea as it requires sequential/recursive calculations to
/// reach any specific index, c.f. the direct multiplication in the step function above.
/// Following this standard allows for wrapper structs to delegate their curves to the curves of
/// their inner types by constructing an inner Fixturator directly with the outer index passed in.
/// If we can always assume the inner fixturators can be efficiently constructed at any index this
/// allows us to efficiently compose fixturators.
/// @see newtype_fixturator! macro defined below for an example of this.
///
/// Fixturator implements Clone for convenience but note that this will clone the current index.
///
/// Fixturators are lazy and infinite, they must never fail to iterate
/// That is to say, calling fixturator.next().unwrap() must be safe to do and never panic
/// This makes the external interface as easy to compose as possible when building up Fixturators
/// over complex data types that include different curves with various periods.
/// For example, the Predictable bool sequence cycles between true/false with period of 2 while the
/// Predictable string sequence has 10 sample strings that it iterates over. We want to be able to
/// easily support Fixturators over structs containing both string and bool fields, so we wrap the
/// inner Fixturator sequences to keep producing bools and Strings for as needed (rather than
/// forcing the outer struct to stop after 2 bools or manually implement ad-hoc wrapping).
/// Wrapping logic may be subtle, e.g. mapping between a usize index and a u8 Item where the max
/// values do not align, so it is best to centralise the wrapping behaviour inside the Iterator
/// implementations for each <Item, Curve> combination.
/// If you are implementing an iteration over some finite sequence then wrap the iteration back to
/// the start of the sequence once the index exceeds the sequence's bounds or reset the index to 0
/// after seq.len() iterations.
/// essentially, the iteration of a fixturator should work like some_iter.cycle()
pub struct Fixturator<Item, Curve> {
    item: std::marker::PhantomData<Item>,
    pub curve: Curve,
    pub index: usize,
}

impl<Curve, Item> Fixturator<Item, Curve> {
    /// constructs a Fixturator of type <Item, Curve> from a Curve and starting index
    /// raw calls are a little verbose, e.g. `Fixturator::<u32, Predictable>::new(Predictable, 0)`
    /// the starting index is exposed to facilitate wrapper structs to delegate their indexes to
    /// internal Fixturators
    /// @see newtype_fixturator! macro below for an example of this
    pub fn new(curve: Curve, start: usize) -> Self {
        Fixturator::<Item, Curve> {
            curve,
            index: start,
            item: std::marker::PhantomData,
        }
    }
}

// /// set of basic tests that can be used to test any FooFixturator implementation
// /// usage:
// /// - type: the Foo of FooFixturator to be tested
// /// - empty_expected: vector of any length of empties that we predict from Empty
// /// - predictable_expected: vector of any length (can wrap) that we predict from Predictable
// /// - test_unpredictable (optional): whether to try and test the unpredictable case
// /// @see the tests in modules in this crate
#[macro_export]
macro_rules! basic_test {
    ( $type:ty, $empty_expected:expr, $predictable_expected:expr ) => {
        basic_test!($type, $empty_expected, $predictable_expected, true);
    };
    ( $type:ty, $empty_expected:expr, $predictable_expected:expr, $test_unpredictable:literal ) => {
        item! {
            #[test]
            #[cfg(test)]
            fn [<$type:lower _empty>] () {
                let empties = [<$type:camel Fixturator>]::new(Empty);
                // we can make many empties from the Empty curve
                assert_eq!(
                    $empty_expected,
                    empties.take($empty_expected.len()).collect::<Vec<$type>>(),
                );
            }
        }

        item! {
            #[test]
            #[cfg(test)]
            fn [<$type:lower _predictable>] () {
                let predictables = [<$type:camel Fixturator>]::new(Predictable);
                // we can predict some vector of values from the Predictable curve
                assert_eq!(
                    $predictable_expected,
                    predictables.take($predictable_expected.len()).collect::<Vec<$type>>(),
                );
            }
        }

        item! {
            #[test]
            #[cfg(test)]
            fn [<$type:lower _unpredictable>] () {
                if $test_unpredictable {
                    let empties = [<$type:camel Fixturator>]::new(Empty);
                    let unpredictables = [<$type:camel Fixturator>]::new(Unpredictable);

                    // the Unpredictable curve is not Empty
                    assert_ne!(
                        empties.take(100).collect::<Vec<$type>>(),
                        unpredictables.take(100).collect::<Vec<$type>>(),
                    );

                    let predictables = [<$type:camel Fixturator>]::new(Predictable);
                    let unpredictables = [<$type:camel Fixturator>]::new(Unpredictable);

                    // the Unpredictable curve is not Predictable
                    assert_ne!(
                        predictables.take(100).collect::<Vec<$type>>(),
                        unpredictables.take(100).collect::<Vec<$type>>(),
                    );
                }
            }
        }
    };
}

/// implements a FooFixturator for any type Foo
/// this simply wraps Fixturator<Foo, Curve> up as FooFixturator<Curve>
///
/// this macro serves a few purposes:
/// - we avoid the orphan rule that would prevent us implementing Iterator on Fixturator directly
/// - we avoid the verbosity of type and impl juggling around every new FooFixturator
/// - we create a FooFixturator implementation that is compatible with basic_test! macro
/// - we cover all three basic curves
/// - we standardiize the new() and new_indexed() methods without relying on traits
///
/// the expressions passed into the macro are the body of the next calls for Empty, Unpredictable
/// and Predictable, in order
#[macro_export]
macro_rules! fixturator {
    ( $type:ident, $empty:expr, $unpredictable:expr, $predictable:expr ) => {
        item! {
            #[allow(missing_docs)]
            pub struct [<$type:camel Fixturator>]<Curve>(Fixturator<$type, Curve>);

            #[allow(missing_docs)]
            impl <Curve>[<$type:camel Fixturator>]<Curve> {
                pub fn new(curve: Curve) -> [<$type:camel Fixturator>]<Curve> {
                    Self::new_indexed(curve, 0)
                }
                pub fn new_indexed(curve: Curve, start: usize) -> [<$type:camel Fixturator>]<Curve> {
                    [<$type:camel Fixturator>](Fixturator::<$type, Curve>::new(curve, start))
                }
            }

            #[allow(missing_docs)]
            impl Iterator for [<$type:camel Fixturator>]<Empty> {
                type Item = $type;

                /// false has an empty ring to it
                fn next(&mut self) -> Option<Self::Item> {
                    Some($empty)
                }
            }

            #[allow(missing_docs)]
            impl Iterator for [<$type:camel Fixturator>]<Unpredictable> {
                type Item = $type;

                /// fallback to default rust randomness
                fn next(&mut self) -> Option<Self::Item> {
                    Some($unpredictable)
                }
            }

            #[allow(missing_docs)]
            impl Iterator for [<$type:camel Fixturator>]<Predictable> {
                type Item = $type;

                /// simple alternation between true/false vals starting with true
                fn next(&mut self) -> Option<Self::Item> {
                    Some($predictable)
                }
            }
        }
    };
}

/// represents an unpredictable curve
///
/// unpredictable curves seek to:
/// - disrupt 'just so' implementations of algorithms that lean too heavily on fragile assumptions
/// - have a high probability of generating common edge cases that developers fail to cover
/// a classic example is broken/forgotten NaN handling in code that uses floats for calculations
///
/// in general this is what we want from our tests, to remind us of where we are _wrong_ about our
/// assumptions in our code.
/// it is likely that you want to use the Unpredictable curve as the defacto choice for testing.
///
/// however, note that unpredictable curves are NOT intended:
/// - to comprehensively cover any particular value space
/// - to replace property/fuzz testing
/// - to algorithmically explore edge-cases in an automated fashion
/// - to assert any particular security or correctness concern
///
/// unpredictable curves are a great way to knock off some low hanging fruit, especially around
/// numeric calculations and utf-8 handling, but are no replacement for stringent approaches.
#[derive(Clone)]
pub struct Unpredictable;

/// represents a predictable curve
///
/// a predictable curve simply iterates over some known progression of values in the same way every
/// test run.
///
/// predictable curves can be convenient, or even necessary, if an unpredictable curve breaks our
/// ability to make specific assertions about our code.
///
/// for example, we may want to demonstrate that additon works.
/// with an unpredictable curve we can assert things like the arguments being commutative,
/// associative, additive, etc. but then we quickly end up doing a bad version of property testing.
/// better to assert known expected results of addition from various values from a predictable
/// curve and then subject the addition function to real property testing with a dedicated tool.
///
/// this curve is provided as a standard option because there is a real, common tradeoff between
/// test fragility (accuracy) and specificity (precision).
#[derive(Clone)]
pub struct Predictable;

/// represents a curve over the empty value(s)
/// the concept of "empty" is as slippery as it is of dubious value
/// how many countless hours and bugs have we lost over deciding what "is" and what "isn't"?
/// i'm looking at you, JS and PHP -_-
///
/// regardless, collections with no items, numbers with no magnitude, strings with no chars are all
/// common sources of bugs, so feel free to manifest as much emptiness as you like from this curve.
#[derive(Clone)]
pub struct Empty;

#[macro_export]
/// a direct delegation of fixtures to the inner type for new types
macro_rules! newtype_fixturator {
    ( $outer:ident<$inner:ty> ) => {
        fixturator!(
            $outer,
            {
                let mut fixturator =
                    expr! { [<$inner:camel Fixturator>]::new_indexed(Empty, self.0.index) };
                self.0.index = self.0.index + 1;
                $outer(fixturator.next().unwrap())
            },
            {
                let mut fixturator =
                    expr! { [<$inner:camel Fixturator>]::new_indexed(Unpredictable, self.0.index) };
                self.0.index = self.0.index + 1;
                $outer(fixturator.next().unwrap())
            },
            {
                let mut fixturator =
                    expr! { [<$inner:camel Fixturator>]::new_indexed(Predictable, self.0.index) };
                self.0.index = self.0.index + 1;
                $outer(fixturator.next().unwrap())
            }
        );
    };
}

#[macro_export]
/// a direct delegation of fixtures to the inner type for wasm io types
/// @see zome types crate
macro_rules! wasm_io_fixturator {
    ( $outer:ident<$inner:ty> ) => {
        fixturator!(
            $outer,
            {
                let mut fixturator =
                    expr! { [<$inner:camel Fixturator>]::new_indexed(Empty, self.0.index) };
                self.0.index = self.0.index + 1;
                $outer::new(fixturator.next().unwrap())
            },
            {
                let mut fixturator =
                    expr! { [<$inner:camel Fixturator>]::new_indexed(Unpredictable, self.0.index) };
                self.0.index = self.0.index + 1;
                $outer::new(fixturator.next().unwrap())
            },
            {
                let mut fixturator =
                    expr! { [<$inner:camel Fixturator>]::new_indexed(Predictable, self.0.index) };
                self.0.index = self.0.index + 1;
                $outer::new(fixturator.next().unwrap())
            }
        );
    };
}

#[macro_export]
/// Creates a simple way to generate enums that use the strum way of iterating
/// https://docs.rs/strum/0.18.0/strum/
/// iterates over all the variants (Predictable) or selects random variants (Unpredictable)
/// You do still need to BYO "empty" variant as the macro doesn't know what to use there
macro_rules! enum_fixturator {
    ( $enum:ident, $empty:expr ) => {
        use crate::strum::IntoEnumIterator;
        use rand::seq::IteratorRandom;
        fixturator!(
            $enum,
            $empty,
            {
                let mut rng = rand::thread_rng();
                $enum::iter().choose(&mut rng).unwrap()
            },
            {
                let ret = $enum::iter().cycle().nth(self.0.index).unwrap();
                self.0.index = self.0.index + 1;
                ret
            }
        );
    };
}