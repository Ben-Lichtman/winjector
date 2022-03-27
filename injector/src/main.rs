#![feature(int_roundings)]

use object::{read::pe::PeFile64, Object};
use std::fs::read;
use windows::Win32::System::{
	Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE},
	ProcessStatus::LIST_MODULES_ALL,
	Threading::THREAD_CREATE_RUN_IMMEDIATELY,
};
use winjector::{
	helpers::{get_process_by_file_name, rva2offset},
	windows_wrapper::thread::Thread,
};

fn reflective() {
	let target_name = "notepad.exe";
	let dll_path = r"C:\Users\Ben\dev\rust\winjector\target\release\example.dll";
	let loader = "reflective_loader";

	// read DLL
	let dll_raw = read(dll_path).unwrap();
	let dll = PeFile64::parse(dll_raw.as_slice()).unwrap();

	// Find loader function within
	let loader_export = dll
		.exports()
		.unwrap()
		.into_iter()
		.find(|e| e.name() == loader.as_bytes())
		.unwrap();
	println!("{:x?}", loader_export);
	let loader_addr_rva = loader_export.address() as _;

	// Translate to file offset
	let loader_addr_offset = rva2offset(&dll, loader_addr_rva).unwrap();
	println!(
		"=> Found loader function at offset {:x}",
		loader_addr_offset
	);

	// Find target process
	let mut targets = get_process_by_file_name(target_name);
	if targets.is_empty() {
		panic!("process not found");
	}
	let (target_path, target) = targets.swap_remove(0);
	println!("=> Found {}", target_path);

	let target_pid = target.pid().unwrap();
	println!("=> PID: {}", target_pid);

	// Allocate space in target process
	let space_to_allocate = dll_raw.len().next_multiple_of(0x1000);
	let allocated = target
		.virtual_alloc(
			0,
			space_to_allocate,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READ,
		)
		.unwrap();
	println!(
		"=> Allocated {:x}B at {:#x} - {:#x}",
		space_to_allocate,
		allocated.address(),
		allocated.address() + allocated.size()
	);

	// Write DLL to allocated space
	allocated.write_memory(&dll_raw, 0).unwrap();
	println!("=> Wrote {:x}B DLL", dll_raw.len());

	// Create remote thread starting at the loader function
	let entry_point = allocated.address() + loader_addr_offset;
	let thread = Thread::spawn_remote(
		&target,
		0,
		entry_point,
		0 as _,
		THREAD_CREATE_RUN_IMMEDIATELY,
	)
	.unwrap();
	println!("=> Spawned thread at address {:x}", entry_point);

	thread.wait(0).unwrap();

	panic!("DONE")
}

fn conventional() {
	let target_name = "notepad.exe";
	let dll_path = r"target\release\example.dll";
	let module = "KERNEL32.DLL";
	let function = "LoadLibraryA";

	// Find target process
	let mut targets = get_process_by_file_name(target_name);
	if targets.is_empty() {
		panic!("process not found");
	}
	let (target_path, target) = targets.swap_remove(0);
	println!("=> Found {}", target_path);

	let target_pid = target.pid().unwrap();
	println!("=> PID: {}", target_pid);

	let modules = target.enum_modules(LIST_MODULES_ALL).unwrap();
	let kernel32 = modules
		.into_iter()
		.find(|m| m.base_name().unwrap() == module.as_bytes())
		.unwrap();
	println!("=> Found {}", module);

	let function_address = kernel32.export_address(function).unwrap();

	let allocation = target
		.virtual_alloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
		.unwrap();
	allocation.write_memory(dll_path.as_bytes(), 0).unwrap();

	Thread::spawn_remote(
		&target,
		0,
		function_address,
		allocation.address() as _,
		THREAD_CREATE_RUN_IMMEDIATELY,
	)
	.unwrap();
}

fn main() {
	// conventional();
	reflective();
}
