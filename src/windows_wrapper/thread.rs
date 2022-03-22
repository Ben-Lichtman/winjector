use crate::{
	error::{Error, Result},
	windows_wrapper::process::Process,
};
use std::ffi::c_void;
use windows::Win32::{
	Foundation::{CloseHandle, FILETIME, HANDLE, WAIT_FAILED},
	System::{
		Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT},
		Threading::{
			CreateRemoteThreadEx, GetExitCodeThread, GetThreadTimes, OpenThread, ResumeThread,
			SuspendThread, WaitForSingleObjectEx, LPPROC_THREAD_ATTRIBUTE_LIST,
			LPTHREAD_START_ROUTINE, THREAD_ACCESS_RIGHTS, THREAD_CREATION_FLAGS,
		},
	},
};

pub type StartRoutine = LPTHREAD_START_ROUTINE;

pub struct Thread {
	handle: HANDLE,
}

impl Thread {
	pub fn from_tid(access: THREAD_ACCESS_RIGHTS, inherit: bool, tid: u32) -> Result<Self> {
		let handle = unsafe { OpenThread(access, inherit, tid).ok()? };
		Ok(Self { handle })
	}

	pub fn spawn_remote(
		process: &Process,
		stack_size: usize,
		entry: StartRoutine,
		param: *const c_void,
		flags: THREAD_CREATION_FLAGS,
	) -> Result<Self> {
		let param = param;
		let mut thread_id = 0;
		let handle = unsafe {
			CreateRemoteThreadEx(
				process.handle(),
				0 as _,
				stack_size,
				entry,
				param,
				flags.0,
				LPPROC_THREAD_ATTRIBUTE_LIST::default(),
				&mut thread_id,
			)
			.ok()?
		};
		Ok(Self { handle })
	}

	pub fn wait(&self, milliseconds: u32) -> Result<u32> {
		let cause = unsafe { WaitForSingleObjectEx(self.handle, milliseconds, false) };
		if cause == WAIT_FAILED.0 {
			return Err(Error::ApiCallFailed);
		}
		Ok(cause)
	}

	pub fn exit_code(&self) -> Result<u32> {
		let mut code = 0;
		unsafe {
			GetExitCodeThread(self.handle, &mut code).ok()?;
		}
		Ok(code)
	}

	pub fn thread_times(&self) -> Result<[FILETIME; 4]> {
		let mut times = [FILETIME::default(); 4];
		unsafe {
			GetThreadTimes(
				self.handle,
				&mut times[0],
				&mut times[1],
				&mut times[2],
				&mut times[3],
			)
			.ok()?;
		}
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
		let mut context = CONTEXT {
			ContextFlags: flags,
			..Default::default()
		};
		unsafe {
			GetThreadContext(self.handle, &mut context).ok()?;
		}
		Ok(context)
	}

	pub fn set_context(&self, context: &CONTEXT) -> Result<()> {
		unsafe {
			SetThreadContext(self.handle, context).ok()?;
		}
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
