use crate::{
	error::{Error, Result},
	windows_wrapper::process::Process,
};
use windows::Win32::System::Memory::{
	VirtualAllocEx, VirtualFreeEx, MEM_RELEASE, PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE,
};
pub struct VirtualAlloc<'a> {
	process: &'a Process,
	address: usize,
	size: usize,
}

impl<'a> VirtualAlloc<'a> {
	pub fn alloc(
		process: &'a Process,
		address: usize,
		size: usize,
		alloc_type: VIRTUAL_ALLOCATION_TYPE,
		protect: PAGE_PROTECTION_FLAGS,
	) -> Result<Self> {
		let address =
			unsafe { VirtualAllocEx(process.handle(), address as _, size, alloc_type, protect) };
		if address.is_null() {
			return Err(Error::ApiCallFailed);
		}
		Ok(Self {
			process,
			address: address as _,
			size,
		})
	}

	pub fn free(self) {
		let err = unsafe {
			VirtualFreeEx(
				self.process.handle(),
				self.address as _,
				self.size,
				MEM_RELEASE,
			)
		};
		err.expect("Virtual alloc could not be freed");
	}

	pub fn process(&self) -> &Process { self.process }

	pub fn address(&self) -> usize { self.address }

	pub fn size(&self) -> usize { self.size }

	pub fn read_memory(&self, data: &mut [u8], offset: usize) -> Result<usize> {
		self.process.read_memory(data, self.address + offset)
	}

	pub fn write_memory(&self, data: &[u8], offset: usize) -> Result<usize> {
		self.process.write_memory(data, self.address + offset)
	}

	pub fn virtual_protect(
		&self,
		offset: usize,
		size: usize,
		flag: PAGE_PROTECTION_FLAGS,
	) -> Result<PAGE_PROTECTION_FLAGS> {
		self.process
			.virtual_protect(self.address + offset, size, flag)
	}
}
