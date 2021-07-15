use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
	#[error("an API call failed")]
	ApiCallFailed,
	#[error("an API call returned nothing")]
	ApiCallNone,
	#[error("failed to close a handle")]
	HandleClose,
	#[error("tried to free a null pointer")]
	NullFree,
	#[error("error converting strings")]
	StringErr,
	#[error(transparent)]
	IoErr(#[from] std::io::Error),
	#[error(transparent)]
	UTF8Err(#[from] std::str::Utf8Error),
}
