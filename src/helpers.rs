use windows::Win32::System::{ProcessStatus::LIST_MODULES_ALL, Threading::PROCESS_ALL_ACCESS};

use crate::windows_wrapper::{
	module::Module,
	process::{enum_process_ids, Process},
};

pub fn get_process_by_file_name(name: &str) -> Option<(String, Process)> {
	let pids = enum_process_ids().unwrap();
	pids.into_iter()
		.filter_map(|pid| Process::from_pid(pid, PROCESS_ALL_ACCESS, false).ok())
		.map(|p| {
			let fname = p.get_file_name().unwrap();
			(String::from_utf8(fname).unwrap(), p)
		})
		.find(|(file, _)| file.ends_with(name))
}

pub fn get_module_by_file_name<'a>(
	process: &'a Process,
	name: &str,
) -> Option<(String, Module<'a>)> {
	process
		.enum_modules(LIST_MODULES_ALL)
		.unwrap()
		.into_iter()
		.map(|m| {
			let fname = m.file_name().unwrap();
			(String::from_utf8(fname).unwrap(), m)
		})
		.find(|(file, _)| file.ends_with(name))
}
