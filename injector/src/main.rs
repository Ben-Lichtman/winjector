#![feature(int_roundings)]

use object::{read::pe::PeFile64, Object};
use std::fs::read;
use windows::Win32::System::{
	Diagnostics::ToolHelp::TH32CS_SNAPTHREAD,
	Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE},
	ProcessStatus::LIST_MODULES_ALL,
	Threading::{
		PROCESS_ALL_ACCESS, THREAD_CREATE_RUN_IMMEDIATELY, THREAD_GET_CONTEXT,
		THREAD_QUERY_INFORMATION, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
	},
};
use winjector::{
	helpers::{get_process_by_file_name, rva2offset},
	windows_wrapper::{process::Process, thread::Thread},
};

fn get_dll(path: &str, loader_fn_name: &str) -> (Vec<u8>, usize) {
	// read DLL
	let dll_raw = read(path).unwrap();
	let dll = PeFile64::parse(dll_raw.as_slice()).unwrap();

	// Find loader function within
	let loader_export = dll
		.exports()
		.unwrap()
		.into_iter()
		.find(|e| e.name() == loader_fn_name.as_bytes())
		.unwrap();
	println!("{:x?}", loader_export);
	let loader_addr_rva = loader_export.address() as _;

	// Translate to file offset
	let loader_addr_offset = rva2offset(&dll, loader_addr_rva).unwrap();
	println!(
		"=> Found loader function at offset {:x}",
		loader_addr_offset
	);
	(dll_raw, loader_addr_offset)
}

fn process_from_name(target_name: &str) -> Process {
	// Find target process
	let mut targets = get_process_by_file_name(target_name);
	if targets.is_empty() {
		panic!("process not found");
	}
	// if targets.len() != 1 {
	// 	panic!("multiple processes found");
	// }
	let (target_path, target) = targets.swap_remove(0);
	let target_pid = target.pid().unwrap();
	println!("=> Found {}, PID {}", target_path, target_pid);

	target
}

fn process_from_pid(pid: u32) -> Process {
	let target = Process::from_pid(pid, PROCESS_ALL_ACCESS, true).unwrap();
	println!("=> Found PID: {}", pid);
	target
}

fn inject_process(target: Process, dll_raw: Vec<u8>, loader_addr_offset: usize) {
	let target_pid = target.pid().unwrap();

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
	let _thread = Thread::spawn_remote(
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

fn main() {
	let target_name = "notepad.exe";

	let dll_path = r"target\release\example.dll";
	let loader = "reflective_loader";

	let (dll_raw, loader_addr_offset) = get_dll(dll_path, loader);

	// let target = process_from_pid(6468);
	let target = process_from_name(target_name);
	inject_process(target, dll_raw, loader_addr_offset)
}
