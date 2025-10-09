/// Structure representing if node was already processed by some algorithm of not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessedMarker {
    pub processed: bool,
}
