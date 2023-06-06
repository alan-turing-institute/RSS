pub use canonical_flatten_derive::CanonicalFlatten;
pub trait CanonicalFlatten {
    fn flatten(&self) ->  Vec<String>;
}