use windows::Win32::System::{
	Diagnostics::Debug::PROCESSOR_ARCHITECTURE,
	SystemInformation::{GetSystemInfo, SYSTEM_INFO},
};

pub struct SystemInfo {
	inner: SYSTEM_INFO,
}

impl SystemInfo {
	pub fn processor_architecture(&self) -> PROCESSOR_ARCHITECTURE {
		unsafe { self.inner.Anonymous.Anonymous.wProcessorArchitecture }
	}

	pub fn page_size(&self) -> u32 { self.inner.dwPageSize }

	pub fn min_application_address(&self) -> usize { self.inner.lpMinimumApplicationAddress as _ }

	pub fn max_application_address(&self) -> usize { self.inner.lpMaximumApplicationAddress as _ }

	pub fn processor_mask(&self) -> usize { self.inner.dwActiveProcessorMask }

	pub fn number_of_processors(&self) -> u32 { self.inner.dwNumberOfProcessors }

	pub fn allocation_granularity(&self) -> u32 { self.inner.dwAllocationGranularity }
}

pub fn get_system_info() -> SystemInfo {
	let mut info = SystemInfo {
		inner: SYSTEM_INFO::default(),
	};
	unsafe { GetSystemInfo(&mut info.inner) };
	info
}
