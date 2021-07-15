use std::{ffi::c_void, mem::MaybeUninit, ptr::null_mut};

use crate::{
	bindings::*,
	error::{Error, Result},
	windows_wrapper::process::Process,
};

pub type StartRoutine = LPTHREAD_START_ROUTINE;

pub struct Thread {
	handle: HANDLE,
}

impl Thread {
	pub fn from_tid(access: u32, inherit: bool, tid: u32) -> Result<Self> {
		let handle = unsafe { OpenThread(access, inherit, tid) };
		if handle.is_null() {
			return Err(Error::ApiCallFailed);
		}
		Ok(Self { handle })
	}

	pub fn spawn_remote(
		process: &Process,
		stack_size: usize,
		entry: StartRoutine,
		param: *mut c_void,
		flags: THREAD_CREATION_FLAGS,
	) -> Result<Self> {
		let mut thread_id = 0;
		let handle = unsafe {
			CreateRemoteThreadEx(
				process.handle(),
				0 as _,
				stack_size,
				Some(entry),
				param,
				flags.0,
				LPPROC_THREAD_ATTRIBUTE_LIST(null_mut()),
				&mut thread_id,
			)
		};
		if handle.is_null() {
			return Err(Error::ApiCallFailed)?;
		}
		Ok(Self { handle })
	}

	pub fn wait(&self, milliseconds: u32) -> Result<WAIT_RETURN_CAUSE> {
		let cause = unsafe { WaitForSingleObjectEx(self.handle, milliseconds, false) };
		if cause == WAIT_FAILED {
			return Err(Error::ApiCallFailed);
		}
		Ok(cause)
	}

	pub fn exit_code(&self) -> Result<u32> {
		let mut code = 0;
		let err = unsafe { GetExitCodeThread(self.handle, &mut code) };
		err.ok().map_err(|_| Error::ApiCallFailed)?;
		Ok(code)
	}

	pub fn thread_times(&self) -> Result<[FILETIME; 4]> {
		let mut times = [FILETIME::default(); 4];
		let err = unsafe {
			GetThreadTimes(
				self.handle,
				&mut times[0],
				&mut times[1],
				&mut times[2],
				&mut times[3],
			)
		};
		err.ok().map_err(|_| Error::ApiCallFailed)?;
		Ok(times)
	}

	pub fn suspend(&self) -> Result<u32> {
		let prev_count = unsafe { SuspendThread(self.handle) };
		if prev_count == 0xffffffff {
			return Err(Error::ApiCallFailed);
		}
		Ok(prev_count)
	}

	pub fn resume(&self) -> Result<u32> {
		let prev_count = unsafe { ResumeThread(self.handle) };
		if prev_count == 0xffffffff {
			return Err(Error::ApiCallFailed);
		}
		Ok(prev_count)
	}

	pub fn context(&self, flags: u32) -> Result<CONTEXT> {
		#[repr(align(16))]
		struct ContextWrapper {
			inner: CONTEXT,
		}

		let mut context = ContextWrapper {
			inner: unsafe { MaybeUninit::<CONTEXT>::zeroed().assume_init() },
		};

		context.inner.ContextFlags = flags;

		let err = unsafe { GetThreadContext(self.handle, &mut context.inner) };
		err.ok().map_err(|_| Error::ApiCallFailed)?;
		Ok(context.inner)
	}

	pub fn set_context(&self, context: &mut CONTEXT) -> Result<()> {
		let err = unsafe { SetThreadContext(self.handle, context) };
		err.ok().map_err(|_| Error::ApiCallFailed)?;
		Ok(())
	}
}

impl Drop for Thread {
	fn drop(&mut self) {
		if !self.handle.is_invalid() {
			let err = unsafe { CloseHandle(self.handle) };
			err.expect("Handle could not be closed");
		}
	}
}
