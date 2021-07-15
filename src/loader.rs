use object::{
	pe::{
		ImageBaseRelocation, ImageDataDirectory, ImageDosHeader, ImageImportDescriptor,
		ImageNtHeaders64, ImageSectionHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC,
		IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64,
		IMAGE_REL_BASED_HIGHLOW,
	},
	pod::{from_bytes, from_bytes_mut, slice_from_bytes, slice_from_bytes_mut},
	LittleEndian, U16Bytes,
};
use std::{
	collections::HashMap,
	ffi::CStr,
	fs::read,
	mem::{size_of, transmute},
	ptr::null_mut,
};

use crate::{
	bindings::*,
	helpers::get_module_by_file_name,
	object::pe::Pefile64,
	shellcode,
	windows_wrapper::{
		process::Process,
		snapshot::ThreadEntry,
		thread::{StartRoutine, Thread},
	},
};

pub fn conventional(process: &Process, library_path: &CStr) {
	// Get library handle within process
	let kernel_in_process = get_module_by_file_name(process, "KERNEL32.DLL").unwrap().1;

	// Get function location within library
	let loadlibrary = kernel_in_process.export_address("LoadLibraryA").unwrap();

	// Allocate a string buffer within process
	let data_buffer = process
		.virtual_alloc(0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
		.unwrap();

	// Write library path to string buffer
	data_buffer
		.write_memory(library_path.to_bytes_with_nul(), 0)
		.unwrap();

	// Cast library call buffer to function
	let stub_fn = unsafe { transmute::<_, StartRoutine>(loadlibrary) };

	// Create thread in process - enter at library call
	let _thr = Thread::spawn_remote(
		&process,
		0,
		stub_fn,
		data_buffer.address() as _,
		THREAD_CREATE_RUN_IMMEDIATELY,
	)
	.unwrap();
}

pub fn with_shellcode(process: &Process, library_path: &CStr) {
	// Get library handle within process
	let kernel_in_process = get_module_by_file_name(process, "KERNEL32.DLL").unwrap().1;

	// Get function location within library
	let loadlibrary = kernel_in_process.export_address("LoadLibraryA").unwrap();

	// Allocate a string buffer within process
	let data_buffer = process
		.virtual_alloc(0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
		.unwrap();

	// Write library path to string buffer
	data_buffer
		.write_memory(library_path.to_bytes_with_nul(), 0)
		.unwrap();

	// Allocate a shellcode buffer within process
	let shellcode_buffer = process
		.virtual_alloc(0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
		.unwrap();

	shellcode_buffer
		.write_memory(
			&shellcode::gen_function_call_ret_shellcode(
				loadlibrary as _,
				data_buffer.address() as _,
				0,
				0,
				0,
			),
			0,
		)
		.unwrap();

	// Cast shellcode buffer to function
	let stub_fn = unsafe { transmute::<_, StartRoutine>(shellcode_buffer.address()) };

	// Create thread in process - enter at shellcode
	let _thr = Thread::spawn_remote(
		&process,
		0,
		stub_fn,
		null_mut(),
		THREAD_CREATE_RUN_IMMEDIATELY,
	)
	.unwrap();
}

pub fn with_main_thread(process: &Process, library_path: &CStr) {
	// Get library handle within process
	let kernel_in_process = get_module_by_file_name(process, "KERNEL32.DLL").unwrap().1;

	// Get function location within library
	let loadlibrary = kernel_in_process.export_address("LoadLibraryA").unwrap();

	// Allocate a string buffer within process
	let data_buffer = process
		.virtual_alloc(0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
		.unwrap();

	// Allocate a shellcode buffer within process
	let shellcode_buffer = process
		.virtual_alloc(0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
		.unwrap();

	// Create snapshot of process
	let snap = process.snapshot(TH32CS_SNAPTHREAD).unwrap();

	// Use snapshot to get the main thread id of the process
	let mut best_tid = 0x0;
	let mut best_time = 0xffffffffffffffff;
	let mut thread_entry = ThreadEntry::new(&snap);
	while thread_entry.next().is_ok() {
		if thread_entry.owner_pid() != process.pid().unwrap() {
			continue;
		}
		let thread = Thread::from_tid(0x0040, true, thread_entry.thread_id()).unwrap();
		let thread_times = thread.thread_times().unwrap();
		let time_int =
			thread_times[0].dwLowDateTime as u64 | ((thread_times[0].dwHighDateTime as u64) << 32);
		if time_int < best_time {
			best_time = time_int;
			best_tid = thread_entry.thread_id();
		}
	}

	println!("Main thread: {}", best_tid);

	let main_thread = Thread::from_tid(0x0008 | 0x0010 | 0x0002, true, best_tid).unwrap();

	// Now suspend the main thread
	main_thread.suspend().unwrap();

	// monkey with thread context
	let mut context = main_thread.context(0x100000 | 0x00000001).unwrap();
	let old_rip = context.Rip;
	println!("Old RIP {:x}", old_rip);

	context.ContextFlags |= 0x00100000 | 0x00000001;
	context.Rip = shellcode_buffer.address() as _;

	// Write library path to string buffer
	data_buffer
		.write_memory(library_path.to_bytes_with_nul(), 0)
		.unwrap();

	// Write shellcode to shellcode buffer
	shellcode_buffer
		.write_memory(
			&shellcode::gen_function_call_jump_shellcode(
				old_rip,
				loadlibrary as _,
				data_buffer.address() as _,
				0,
				0,
				0,
			),
			0,
		)
		.unwrap();

	process
		.flush_instruction_cache(shellcode_buffer.address(), shellcode_buffer.size())
		.unwrap();

	main_thread.set_context(&mut context).unwrap();

	main_thread.resume().unwrap();
}

pub fn manual_mapping(process: &Process, library_path: &CStr) {
	// All the bytes of the DLL file
	let mut pe_raw_bytes = read(library_path.to_str().unwrap()).unwrap();

	let mut pe = Pefile64::new(&mut pe_raw_bytes);

	// get information for allocating file
	let image_base = pe.nt_header().optional_header.image_base.get(LittleEndian);
	let size_of_image = pe
		.nt_header()
		.optional_header
		.size_of_image
		.get(LittleEndian);

	println!("Image base: {:#x}", image_base);
	println!("Size of image: {:#x}", size_of_image);

	// Allocate memory for mapping dll into
	let target_base = process
		.virtual_alloc(
			0,
			size_of_image as _,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE,
		)
		.unwrap();

	let reloc_delta = target_base.address() as i64 - image_base as i64;

	println!(
		"Target: {:#x}, delta: {:#x}",
		target_base.address(),
		reloc_delta
	);

	// Get relocations
	let relocations = pe.relocations();

	// Apply relocations
	pe.apply_relocations(relocations, reloc_delta);

	// Update baseimage in optional header
	pe.nt_header_mut()
		.optional_header
		.base_of_code
		.set(LittleEndian, target_base.address() as _);

	// Fix imports
	let dd_imports = pe.data_dir()[IMAGE_DIRECTORY_ENTRY_IMPORT];
	let num_directory_entries =
		dd_imports.size.get(LittleEndian) as usize / size_of::<ImageImportDescriptor>();
	// let import_directory_bytes = &bytes[]
}
