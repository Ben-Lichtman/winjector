use std::str::from_utf8;

use crate::{
	bindings::*,
	error::{Error, Result},
	BUFFER_SIZE,
};

pub struct Window {
	handle: HWND,
}

impl Window {
	pub fn get_window_class_name(&self) -> Result<String> {
		let mut buffer = [0u8; BUFFER_SIZE];
		let n_bytes =
			unsafe { GetClassNameA(self.handle, PSTR(&mut buffer as _), BUFFER_SIZE as _) };
		if n_bytes == 0 {
			return Err(Error::ApiCallNone);
		}
		Ok(String::from(from_utf8(&buffer[..n_bytes as _])?))
	}

	pub fn get_window_text(&self) -> Result<String> {
		let mut buffer = [0u8; BUFFER_SIZE];
		let n_bytes =
			unsafe { GetWindowTextA(self.handle, PSTR(&mut buffer as _), BUFFER_SIZE as _) };
		if n_bytes == 0 {
			return Err(Error::ApiCallNone);
		}
		Ok(String::from(from_utf8(&buffer[..n_bytes as _])?))
	}

	pub fn enum_child_windows(&self) -> Vec<Window> {
		let mut vec = Vec::new();
		unsafe {
			EnumChildWindows(
				self.handle,
				Some(append_window_to_vec),
				LPARAM(&mut vec as *mut _ as _),
			);
		};
		vec
	}

	pub fn send_message(&self, msg: u32, param_a: usize, param_b: usize) -> i32 {
		let LRESULT(result) =
			unsafe { SendMessageA(self.handle, msg, WPARAM(param_a), LPARAM(param_b as _)) };
		result
	}
}

unsafe extern "system" fn append_window_to_vec(window_handle: HWND, parameter: LPARAM) -> BOOL {
	let vec = (parameter.0 as *mut Vec<_>).as_mut().unwrap();
	let handle = Window {
		handle: window_handle,
	};
	vec.push(handle);
	BOOL::from(true)
}

pub fn get_window_handles(thread_id: u32) -> Vec<Window> {
	let mut vec = Vec::new();
	unsafe {
		EnumThreadWindows(
			thread_id,
			Some(append_window_to_vec),
			LPARAM(&mut vec as *mut _ as _),
		);
	};
	vec
}
