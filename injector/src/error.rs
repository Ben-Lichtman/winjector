use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
	#[error("windows error")]
	Windows(#[from] windows::core::Error),
	#[error("API call failed")]
	ApiCallFailed,
	#[error("an API call returned nothing")]
	ApiCallNone,
	#[error("error converting strings")]
	StringErr,
	#[error(transparent)]
	UTF8Err(#[from] std::str::Utf8Error),
	#[error("iced_error")]
	Iced(#[from] iced_x86::IcedError),
}
