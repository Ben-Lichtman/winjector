#![allow(clippy::missing_safety_doc)]

use crate::error::Result;
use std::mem::size_of;
use windows::Win32::{
	Foundation::{CloseHandle, HANDLE},
	System::Diagnostics::ToolHelp::{
		CREATE_TOOLHELP_SNAPSHOT_FLAGS, CreateToolhelp32Snapshot, THREADENTRY32, Thread32First,
		Thread32Next,
	},
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
		let handle = unsafe { CreateToolhelp32Snapshot(flags, pid)? };
		Ok(Self { handle, flags })
	}

	pub fn handle(&self) -> HANDLE { self.handle }

	pub fn flags(&self) -> CREATE_TOOLHELP_SNAPSHOT_FLAGS { self.flags }

	pub fn thread_entries(&self) -> ThreadEntryIter<'_> { ThreadEntryIter::new(self) }
}

impl Drop for Snapshot {
	fn drop(&mut self) {
		if !self.handle.is_invalid() {
			let err = unsafe { CloseHandle(self.handle) };
			err.expect("Handle could not be closed");
		}
	}
}

pub struct ThreadEntryIter<'a> {
	snapshot: &'a Snapshot,
	entry: THREADENTRY32,
	done_first: bool,
}

impl<'a> ThreadEntryIter<'a> {
	pub fn new(snapshot: &'a Snapshot) -> Self {
		let entry = THREADENTRY32 {
			dwSize: size_of::<THREADENTRY32>() as _,
			..THREADENTRY32::default()
		};

		Self {
			snapshot,
			entry,
			done_first: false,
		}
	}
}

impl<'a> Iterator for ThreadEntryIter<'a> {
	type Item = THREADENTRY32;

	fn next(&mut self) -> Option<Self::Item> {
		match self.done_first {
			false => {
				self.done_first = true;
				unsafe {
					Thread32First(self.snapshot.handle, &mut self.entry)
						.ok()
						.map(|_| self.entry)
				}
			}
			true => unsafe {
				Thread32Next(self.snapshot.handle, &mut self.entry)
					.ok()
					.map(|_| self.entry)
			},
		}
	}
}
