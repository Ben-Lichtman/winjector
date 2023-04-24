use crate::{
	error::Result,
	windows_wrapper::{
		module::Module,
		process::{enum_process_ids, Process},
		thread::Thread,
	},
};
use object::{Object, ObjectSegment};
use windows::Win32::System::{
	Diagnostics::ToolHelp::TH32CS_SNAPTHREAD,
	ProcessStatus::LIST_MODULES_ALL,
	Threading::{
		PROCESS_ALL_ACCESS, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SET_CONTEXT,
		THREAD_SUSPEND_RESUME,
	},
};

pub fn rva2offset<'a>(pe: &'a impl Object<'a, 'a>, rva: usize) -> Option<usize> {
	let rva = rva as _;
	pe.segments()
		.map(|s| (s.size(), s.address(), s.file_range().0))
		.find_map(|(s, v, f)| match v <= rva && rva < v + s {
			true => Some((rva - v + f) as _),
			false => None,
		})
}

pub fn get_process_by_file_name(name: &str) -> impl Iterator<Item = (String, Process)> + '_ {
	let pids = enum_process_ids().unwrap();
	pids.into_iter()
		.filter_map(|pid| Process::from_pid(pid, PROCESS_ALL_ACCESS, true).ok())
		.map(|p| {
			let fname = p.get_file_name().unwrap();
			let fname = String::from_utf8(fname).unwrap();
			(fname, p)
		})
		.filter(move |(file, _)| file.ends_with(name))
}

pub fn get_module_by_file_name<'a>(
	process: &'a Process,
	name: &'a str,
) -> impl Iterator<Item = (String, Module<'a>)> + 'a {
	process
		.enum_modules(LIST_MODULES_ALL)
		.unwrap()
		.into_iter()
		.map(|m| {
			let fname = m.file_name().unwrap();
			(String::from_utf8(fname).unwrap(), m)
		})
		.filter(move |(file, _)| file.ends_with(name))
}

pub fn redirect_main_thread(process: &Process, entry: usize) -> Result<()> {
	let target_pid = process.pid()?;

	// Create snapshot of process
	let snap = process.snapshot(TH32CS_SNAPTHREAD).unwrap();

	// Use snapshot to get the main thread id of the process
	let mut best_tid = 0x0;
	let mut best_time = 0xffffffffffffffff;
	for thread_entry in snap.thread_entries() {
		if thread_entry.th32OwnerProcessID != target_pid {
			continue;
		}
		let thread =
			Thread::from_tid(THREAD_QUERY_INFORMATION, true, thread_entry.th32ThreadID).unwrap();
		let thread_times = thread.thread_times().unwrap();
		let time_int =
			thread_times[0].dwLowDateTime as u64 | ((thread_times[0].dwHighDateTime as u64) << 32);
		if time_int < best_time {
			best_time = time_int;
			best_tid = thread_entry.th32ThreadID;
		}
	}
	assert!(best_tid != 0);

	let main_thread = Thread::from_tid(
		THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT,
		true,
		best_tid,
	)
	.unwrap();

	// Now suspend the main thread
	main_thread.suspend().unwrap();

	// monkey with thread context
	let mut context = main_thread.context(0x100000 | 0x00000001).unwrap();
	let _old_rip = context.Rip;

	context.ContextFlags |= 0x00100000 | 0x00000001;
	context.Rip = entry as _;

	// Set thread running again
	main_thread.set_context(&context).unwrap();
	process.flush_instruction_cache(entry, 0x1000).unwrap();
	main_thread.resume().unwrap();

	Ok(())
}
