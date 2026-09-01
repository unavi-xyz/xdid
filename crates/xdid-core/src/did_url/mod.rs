use thiserror::Error;

pub mod relative;
pub mod url;

/// Why a string is not a [`url::DidUrl`] or a [`relative::RelativeDidUrl`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ParseError {
    #[error(transparent)]
    Did(#[from] crate::did::ParseError),
    #[error("path does not start with `/`")]
    PathNotAbsolute,
    #[error("path begins with `//`, which would read as an authority")]
    PathDoubleSlash,
    #[error("invalid path segment")]
    PathSegment,
    #[error("path does not match its variant")]
    PathVariantMismatch,
    #[error("invalid query")]
    Query,
    #[error("invalid fragment")]
    Fragment,
}
