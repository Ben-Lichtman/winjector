use crate::{
	bindings::*,
	windows_wrapper::{
		module::Module,
		process::{enum_process_ids, Process},
	},
};

pub fn get_process_by_file_name(name: &str) -> Option<(String, Process)> {
	let pids = enum_process_ids().unwrap();

	let access = PROCESS_ALL_ACCESS;

	let processes = pids
		.into_iter()
		.filter_map(|pid| Process::from_pid(pid, access, false).ok())
		.map(|p| {
			let fname = p.get_file_name().unwrap();
			(String::from_utf8(fname).unwrap(), p)
		})
		.collect::<Vec<_>>();

	processes.into_iter().find(|(file, _)| file.ends_with(name))
}

pub fn get_module_by_file_name<'a>(
	process: &'a Process,
	name: &str,
) -> Option<(String, Module<'a>)> {
	let modules = process
		.enum_modules(LIST_MODULES_32BIT | LIST_MODULES_64BIT)
		.unwrap()
		.into_iter()
		.map(|m| {
			let fname = m.file_name().unwrap();
			(String::from_utf8(fname).unwrap(), m)
		})
		.collect::<Vec<_>>();

	modules.into_iter().find(|(file, _)| file.ends_with(name))
}
