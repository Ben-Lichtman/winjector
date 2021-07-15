use std::mem::size_of;

use crate::{
	bindings::*,
	error::{Error, Result},
};

pub struct Snapshot {
	handle: HANDLE,
	flags: CREATE_TOOLHELP_SNAPSHOT_FLAGS,
}

impl Snapshot {
	pub unsafe fn from_raw_handle(handle: HANDLE, flags: CREATE_TOOLHELP_SNAPSHOT_FLAGS) -> Self {
		Self { handle, flags }
	}

	pub fn from_pid(pid: u32, flags: CREATE_TOOLHELP_SNAPSHOT_FLAGS) -> Result<Self> {
		let handle = unsafe { CreateToolhelp32Snapshot(flags, pid) };
		if handle.is_invalid() {
			return Err(Error::ApiCallFailed);
		}
		Ok(Self { handle, flags })
	}

	pub fn handle(&self) -> HANDLE { self.handle }

	pub fn flags(&self) -> CREATE_TOOLHELP_SNAPSHOT_FLAGS { self.flags }
}

impl Drop for Snapshot {
	fn drop(&mut self) {
		if !self.handle.is_invalid() {
			let err = unsafe { CloseHandle(self.handle) };
			err.expect("Handle could not be closed");
		}
	}
}

pub struct ThreadEntry<'a> {
	snapshot: &'a Snapshot,
	inner: THREADENTRY32,
	done_first: bool,
}

impl<'a> ThreadEntry<'a> {
	pub fn new(snapshot: &'a Snapshot) -> Self {
		let mut thread_entry_initialise = THREADENTRY32::default();
		thread_entry_initialise.dwSize = size_of::<THREADENTRY32>() as _;
		Self {
			snapshot,
			inner: thread_entry_initialise,
			done_first: false,
		}
	}

	pub fn next(&mut self) -> Result<()> {
		match self.done_first {
			false => {
				let err = unsafe { Thread32First(self.snapshot.handle, &mut self.inner as _) };
				err.ok().map_err(|_| Error::ApiCallFailed)?;
				self.done_first = true;
			}
			true => {
				let err = unsafe { Thread32Next(self.snapshot.handle, &mut self.inner as _) };
				err.ok().map_err(|_| Error::ApiCallFailed)?;
				self.done_first = true;
			}
		}

		Ok(())
	}

	pub fn thread_id(&self) -> u32 {
		assert!(self.done_first);
		self.inner.th32ThreadID
	}

	pub fn owner_pid(&self) -> u32 {
		assert!(self.done_first);
		self.inner.th32OwnerProcessID
	}

	pub fn priority(&self) -> i32 {
		assert!(self.done_first);
		self.inner.tpBasePri
	}
}
