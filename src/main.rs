use winjector::{helpers::get_process_by_file_name, loader};

use std::ffi::CString;

fn main() {
	let process_name = "notepad.exe";

	// Get process handle
	let target = get_process_by_file_name(process_name)
		.expect("application not running")
		.1;

	let target_pid = target.pid().unwrap();
	println!("PID: {}", target_pid);

	let library_path = CString::new(r"C:\Users\Ben\dev\rust\dll\target\release\dll.dll").unwrap();

	println!("Injecting");

	loader::manual_mapping(&target, &library_path);
}
