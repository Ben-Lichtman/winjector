use std::{
	ffi::{c_void, CString},
	mem::size_of,
};

use crate::{
	bindings::*,
	error::{Error, Result},
	windows_wrapper::process::Process,
	BUFFER_SIZE,
};

#[derive(Debug)]
pub struct ModuleInfo {
	inner: MODULEINFO,
}

impl ModuleInfo {
	pub fn base(&self) -> *mut c_void { self.inner.lpBaseOfDll }

	pub fn size(&self) -> u32 { self.inner.SizeOfImage }

	pub fn entry_point(&self) -> *mut c_void { self.inner.EntryPoint }
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
			K32GetModuleBaseNameA(
				self.process.handle(),
				HINSTANCE(self.handle.0),
				PSTR(buf.as_mut_ptr()),
				buf.len() as _,
			)
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
			K32GetModuleFileNameExA(
				self.process.handle(),
				HINSTANCE(self.handle.0),
				PSTR(buf.as_mut_ptr()),
				buf.len() as _,
			)
		};
		if n_bytes == 0 {
			return Err(Error::ApiCallFailed);
		}
		buf.resize(n_bytes as usize, 0);
		Ok(buf)
	}

	pub fn info(&self) -> Result<ModuleInfo> {
		let mut info = ModuleInfo {
			inner: MODULEINFO::default(),
		};
		let err = unsafe {
			K32GetModuleInformation(
				self.process.handle(),
				HINSTANCE(self.handle.0),
				&mut info.inner,
				size_of::<MODULEINFO>() as u32,
			)
		};
		err.ok().map_err(|_| Error::ApiCallFailed)?;
		Ok(info)
	}

	pub fn export_address(&self, name: &str) -> Result<usize> {
		let export_name = match CString::new(name) {
			Ok(s) => s,
			Err(_) => return Err(Error::StringErr),
		};
		let address =
			unsafe { GetProcAddress(HINSTANCE(self.handle.0), PSTR(export_name.as_ptr() as _)) };
		match address {
			None => return Err(Error::StringErr),
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
