use crate::{
	bindings::*,
	error::{Error, Result},
	windows_wrapper::{module::Module, snapshot::Snapshot, virtual_alloc::VirtualAlloc},
	BUFFER_SIZE,
};

use std::mem::size_of;

pub struct MemoryBasicInfo {
	inner: MEMORY_BASIC_INFORMATION,
}

impl MemoryBasicInfo {
	pub fn base_address(&self) -> usize { self.inner.BaseAddress as _ }

	pub fn allocation_base(&self) -> usize { self.inner.AllocationBase as _ }

	pub fn allocation_protect(&self) -> PAGE_TYPE { PAGE_TYPE::from(self.inner.AllocationProtect) }

	pub fn region_size(&self) -> usize { self.inner.RegionSize as _ }

	pub fn state(&self) -> VIRTUAL_ALLOCATION_TYPE {
		VIRTUAL_ALLOCATION_TYPE::from(self.inner.State)
	}

	pub fn protect(&self) -> PAGE_TYPE { PAGE_TYPE::from(self.inner.Protect) }

	pub fn memory_type(&self) -> u32 { self.inner.Type }
}

#[derive(Debug)]
pub struct Process {
	handle: HANDLE,
}

impl Process {
	pub unsafe fn from_raw_handle(handle: HANDLE) -> Self { Self { handle } }

	pub fn current() -> Self {
		let handle = unsafe { GetCurrentProcess() };
		Self { handle }
	}

	pub fn from_pid(pid: u32, access: PROCESS_ACCESS_RIGHTS, inherit: bool) -> Result<Self> {
		let handle = unsafe { OpenProcess(access, inherit, pid) };
		if handle.is_null() {
			return Err(Error::ApiCallFailed);
		}
		Ok(Self { handle })
	}

	pub fn handle(&self) -> HANDLE { self.handle }

	pub fn pid(&self) -> Result<u32> {
		let pid = unsafe { GetProcessId(self.handle) };
		if pid == 0 {
			return Err(Error::ApiCallFailed);
		}
		Ok(pid)
	}

	pub fn snapshot(&self, flags: CREATE_TOOLHELP_SNAPSHOT_FLAGS) -> Result<Snapshot> {
		Snapshot::from_pid(self.pid()?, flags)
	}

	pub fn virtual_query(&self, address: usize) -> Result<MemoryBasicInfo> {
		let mut info = MemoryBasicInfo {
			inner: MEMORY_BASIC_INFORMATION::default(),
		};
		let err = unsafe {
			VirtualQueryEx(
				self.handle,
				address as _,
				&mut info.inner,
				size_of::<MEMORY_BASIC_INFORMATION>(),
			)
		};
		if err == 0 {
			return Err(Error::ApiCallFailed);
		}
		Ok(info)
	}

	pub fn virtual_alloc(
		&self,
		address: usize,
		size: usize,
		alloc_type: VIRTUAL_ALLOCATION_TYPE,
		protect: PAGE_TYPE,
	) -> Result<VirtualAlloc> {
		VirtualAlloc::alloc(self, address, size, alloc_type, protect)
	}

	pub fn get_file_name<'a>(&self) -> Result<Vec<u8>> {
		let mut buf = vec![0u8; BUFFER_SIZE];
		let n_bytes = unsafe {
			K32GetModuleFileNameExA(
				self.handle,
				HINSTANCE(0),
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

	pub fn enum_modules(&self, filter: u32) -> Result<Vec<Module>> {
		let mut module_handles = [HINSTANCE::default(); BUFFER_SIZE];
		let mut bytes_returned = 0u32;
		let err = unsafe {
			K32EnumProcessModulesEx(
				self.handle,
				module_handles.as_mut_ptr() as _,
				(module_handles.len() * size_of::<HINSTANCE>()) as _,
				&mut bytes_returned,
				filter,
			)
		};
		err.ok().map_err(|_| Error::ApiCallFailed)?;
		let items_returned = bytes_returned as usize / size_of::<HINSTANCE>();
		let modules = module_handles[..items_returned]
			.iter()
			.copied()
			.map(|HINSTANCE(pointer)| HANDLE(pointer))
			.map(|h| unsafe { Module::from_raw_handle(h, &self) })
			.collect::<Vec<_>>();
		Ok(modules)
	}

	pub fn virtual_protect(
		&self,
		address: usize,
		size: usize,
		flag: PAGE_TYPE,
	) -> Result<PAGE_TYPE> {
		let mut old_protect = PAGE_TYPE::default();

		let err =
			unsafe { VirtualProtectEx(self.handle, address as _, size, flag, &mut old_protect) };
		err.ok().map_err(|_| Error::ApiCallFailed)?;
		Ok(old_protect)
	}

	pub fn read_memory(&self, buf: &mut [u8], address: usize) -> Result<usize> {
		let mut bytes_read = 0;
		let err = unsafe {
			ReadProcessMemory(
				self.handle,
				address as _,
				buf.as_mut_ptr() as _,
				buf.len(),
				&mut bytes_read,
			)
		};
		err.ok().map_err(|_| Error::ApiCallFailed)?;
		Ok(bytes_read)
	}

	pub fn write_memory(&self, buf: &[u8], address: usize) -> Result<usize> {
		let mut bytes_written = 0;
		let err = unsafe {
			WriteProcessMemory(
				self.handle,
				address as _,
				buf.as_ptr() as _,
				buf.len(),
				&mut bytes_written,
			)
		};
		err.ok().map_err(|_| Error::ApiCallFailed)?;
		Ok(bytes_written)
	}

	pub fn flush_instruction_cache(&self, address: usize, size: usize) -> Result<()> {
		let err = unsafe { FlushInstructionCache(self.handle, address as _, size) };
		err.ok().map_err(|_| Error::ApiCallFailed)?;
		Ok(())
	}
}

impl Drop for Process {
	fn drop(&mut self) {
		if !self.handle.is_invalid() {
			let err = unsafe { CloseHandle(self.handle) };
			err.expect("Handle could not be closed");
		}
	}
}

pub fn enum_process_ids() -> Result<Vec<u32>> {
	let mut array = vec![0u32; BUFFER_SIZE];
	let mut bytes_returned = 0u32;
	let err = unsafe {
		K32EnumProcesses(
			array.as_mut_ptr(),
			(array.len() * size_of::<u32>()) as u32,
			&mut bytes_returned as _,
		)
	};
	err.ok().map_err(|_| Error::ApiCallFailed)?;
	let items_returned = bytes_returned as usize / size_of::<u32>();
	array.resize(items_returned, 0);
	Ok(array)
}
