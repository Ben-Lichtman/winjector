#![allow(clippy::missing_safety_doc)]

use crate::{
	error::{Error, Result},
	windows_wrapper::process::Process,
	BUFFER_SIZE,
};
use std::{ffi::CString, mem::size_of};
use windows::{
	core::PCSTR,
	Win32::{
		Foundation::{HANDLE, HINSTANCE},
		System::{
			LibraryLoader::GetProcAddress,
			ProcessStatus::{
				K32GetModuleBaseNameA, K32GetModuleFileNameExA, K32GetModuleInformation, MODULEINFO,
			},
		},
	},
};

#[derive(Debug, Default)]
pub struct ModuleInfo {
	pub inner: MODULEINFO,
}

impl ModuleInfo {
	pub fn base(&self) -> usize { self.inner.lpBaseOfDll as _ }

	pub fn size(&self) -> u32 { self.inner.SizeOfImage }

	pub fn entry_point(&self) -> usize { self.inner.EntryPoint as _ }
}

#[derive(Debug)]
pub struct Module<'a> {
	handle: HANDLE,
	process: &'a Process,
}

impl<'a> Module<'a> {
	pub unsafe fn from_raw_handle(handle: HANDLE, process: &'a Process) -> Self {
		Self { handle, process }
	}

	pub fn handle(&self) -> HANDLE { self.handle }

	pub fn process(&self) -> &Process { self.process }

	pub fn base_name(&self) -> Result<Vec<u8>> {
		let mut buf = vec![0u8; BUFFER_SIZE];
		let n_bytes = unsafe {
			K32GetModuleBaseNameA(self.process.handle(), HINSTANCE(self.handle.0), &mut buf)
		};
		if n_bytes == 0 {
			return Err(Error::ApiCallFailed);
		}
		buf.resize(n_bytes as usize, 0);
		Ok(buf)
	}

	pub fn file_name(&self) -> Result<Vec<u8>> {
		let mut buf = vec![0u8; BUFFER_SIZE];
		let n_bytes = unsafe {
			K32GetModuleFileNameExA(self.process.handle(), HINSTANCE(self.handle.0), &mut buf)
		};
		if n_bytes == 0 {
			return Err(Error::ApiCallFailed);
		}
		buf.resize(n_bytes as usize, 0);
		Ok(buf)
	}

	pub fn info(&self) -> Result<ModuleInfo> {
		let mut info = ModuleInfo::default();
		unsafe {
			K32GetModuleInformation(
				self.process.handle(),
				HINSTANCE(self.handle.0),
				&mut info.inner,
				size_of::<MODULEINFO>() as u32,
			)
			.ok()?;
		}
		Ok(info)
	}

	pub fn export_address(&self, name: &str) -> Result<usize> {
		let export_name = match CString::new(name) {
			Ok(s) => s,
			Err(_) => return Err(Error::StringErr),
		};
		let address =
			unsafe { GetProcAddress(HINSTANCE(self.handle.0), PCSTR(export_name.as_ptr() as _)) };
		match address {
			None => Err(Error::ApiCallNone),
			Some(a) => Ok(a as _),
		}
	}
}

// impl<'a> Drop for Module<'a> {
// 	fn drop(&mut self) {
// 		if !self.handle.is_invalid() {
// 			let err = unsafe { CloseHandle(self.handle) };
// 			err.expect("Handle could not be closed");
// 		}
// 	}
// }
