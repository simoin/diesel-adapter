#[macro_use]
extern crate diesel;

#[cfg(not(feature = "sqlite"))]
mod adapter;
mod error;

#[macro_use]
mod macros;
mod models;
mod schema;

#[cfg(not(feature = "sqlite"))]
mod actions;

#[cfg(feature = "sqlite")]
mod sqlite;

#[cfg(feature = "sqlite")]
pub use sqlite::actions;
#[cfg(feature = "sqlite")]
pub use sqlite::adapter;

pub use casbin;

pub use adapter::DieselAdapter;
pub use error::Error;
