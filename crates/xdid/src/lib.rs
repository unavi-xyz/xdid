//! Simple [DID](https://www.w3.org/TR/did-core/) library.
//!
//! Add support for new methods using the [Method](xdid_core::Method) trait,
//! then create a [Resolver](resolver::Resolver) to parse and resolve DIDs.

mod resolver;

pub use resolver::*;

pub mod core {
    pub use xdid_core::*;
}

pub mod methods {
    #[cfg(feature = "did-key")]
    pub use xdid_method_key::*;
    #[cfg(feature = "did-web")]
    pub use xdid_method_web::*;
}
