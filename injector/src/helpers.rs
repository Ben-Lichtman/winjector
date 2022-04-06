use crate::windows_wrapper::{
	module::Module,
	process::{enum_process_ids, Process},
};
use object::{Object, ObjectSegment};
use windows::Win32::System::{ProcessStatus::LIST_MODULES_ALL, Threading::PROCESS_ALL_ACCESS};

pub fn rva2offset<'a>(pe: &'a impl Object<'a, 'a>, rva: usize) -> Option<usize> {
	let rva = rva as _;
	pe.segments()
		.map(|s| (s.size(), s.address(), s.file_range().0))
		.find_map(|(s, v, f)| match v <= rva && rva < v + s {
			true => Some((rva - v + f) as _),
			false => None,
		})
}

pub fn get_process_by_file_name(name: &str) -> Vec<(String, Process)> {
	let pids = enum_process_ids().unwrap();
	pids.into_iter()
		.filter_map(|pid| Process::from_pid(pid, PROCESS_ALL_ACCESS, true).ok())
		.map(|p| {
			let fname = p.get_file_name().unwrap();
			let fname = String::from_utf8(fname).unwrap();
			(fname, p)
		})
		.filter(|(file, _)| file.ends_with(name))
		.collect()
}

pub fn get_module_by_file_name<'a>(process: &'a Process, name: &str) -> Vec<(String, Module<'a>)> {
	process
		.enum_modules(LIST_MODULES_ALL)
		.unwrap()
		.into_iter()
		.map(|m| {
			let fname = m.file_name().unwrap();
			(String::from_utf8(fname).unwrap(), m)
		})
		.filter(|(file, _)| file.ends_with(name))
		.collect()
}
