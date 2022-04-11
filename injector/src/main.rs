#![feature(int_roundings)]

use object::{read::pe::PeFile64, Object};
use std::fs::read;
use windows::Win32::System::{
	Diagnostics::ToolHelp::TH32CS_SNAPTHREAD,
	Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE},
	ProcessStatus::LIST_MODULES_ALL,
	Threading::{
		THREAD_CREATE_RUN_IMMEDIATELY, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
		THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
	},
};
use winjector::{
	helpers::{get_process_by_file_name, rva2offset},
	windows_wrapper::{snapshot::ThreadEntryIter, thread::Thread},
};

fn reflective(target_name: &str) {
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

	let entry_point = allocated.address() + loader_addr_offset;
	println!("=> Entry point {:x}", entry_point);

	// Create remote thread starting at the loader function
	let thread = Thread::spawn_remote(
		&target,
		0,
		entry_point,
		0 as _,
		THREAD_CREATE_RUN_IMMEDIATELY,
	)
	.unwrap();
	println!("=> Spawned thread at address {:x}", entry_point);

	// // Create snapshot of process
	// let snap = target.snapshot(TH32CS_SNAPTHREAD).unwrap();
	// // Use snapshot to get the main thread id of the process
	// let mut best_tid = 0x0;
	// let mut best_time = 0xffffffffffffffff;
	// for thread_entry in snap.thread_entries() {
	// 	if thread_entry.th32OwnerProcessID != target_pid {
	// 		continue;
	// 	}
	// 	let thread =
	// 		Thread::from_tid(THREAD_QUERY_INFORMATION, true, thread_entry.th32ThreadID).unwrap();
	// 	let thread_times = thread.thread_times().unwrap();
	// 	let time_int =
	// 		thread_times[0].dwLowDateTime as u64 | ((thread_times[0].dwHighDateTime as u64) << 32);
	// 	if time_int < best_time {
	// 		best_time = time_int;
	// 		best_tid = thread_entry.th32ThreadID;
	// 	}
	// }
	// assert!(best_tid != 0);

	// println!("=> Found main thread with id {}", best_tid);

	// let main_thread = Thread::from_tid(
	// 	THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT,
	// 	true,
	// 	best_tid,
	// )
	// .unwrap();

	// // Now suspend the main thread
	// main_thread.suspend().unwrap();

	// // monkey with thread context
	// let mut context = main_thread.context(0x100000 | 0x00000001).unwrap();
	// let old_rip = context.Rip;
	// println!("=> Old RIP {:x}", old_rip);

	// context.ContextFlags |= 0x00100000 | 0x00000001;
	// context.Rip = entry_point as _;

	// main_thread.set_context(&mut context).unwrap();

	// target
	// 	.flush_instruction_cache(allocated.address(), allocated.size())
	// 	.unwrap();

	// main_thread.resume().unwrap();

	// panic!("DONE")
}

fn conventional(target_name: &str) {
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
	let target_name = "notepad.exe";
	// conventional();
	reflective(target_name);
}
