use reloader as _;
use std::{
	env,
	ffi::c_void,
	fs::{self, File},
	io::Write,
};
use windows::{
	core::PCSTR,
	Win32::{
		Foundation::HWND,
		UI::WindowsAndMessaging::{MessageBoxA, MB_OK},
	},
};

#[no_mangle]
#[allow(non_snake_case)]
extern "system" fn DllMain(_dll_module: i64, call_reason: i32, _reserved: *const c_void) -> i32 {
	const DLL_PROCESS_ATTACH: i32 = 1;
	const DLL_PROCESS_DETACH: i32 = 0;

	// unsafe { core::arch::asm!("int3") }

	match call_reason {
		DLL_PROCESS_ATTACH => attach(),
		DLL_PROCESS_DETACH => (),
		_ => (),
	}
	1
}

fn attach() {
	let message = "pwned\0";

	unsafe {
		MessageBoxA(
			HWND::default(),
			PCSTR(message.as_ptr()),
			PCSTR(message.as_ptr()),
			MB_OK,
		)
	};

	// write_file(&env::var("TMP").unwrap());
	// write_file("C:\\pwned");
}

fn write_file(path: &str) {
	fs::create_dir_all(path).unwrap();
	let pid = std::process::id().to_string();
	let username = env::var("USERNAME").unwrap();
	let domain = env::var("USERDOMAIN").unwrap();
	let path = format!("{}\\pwned_{}.txt", path, pid);
	let process_path = std::env::current_exe().unwrap();
	let args: Vec<String> = std::env::args().collect();

	let output = format!(
		r"[*]          Pid: {:?}
[*]      Process: {:?}
[*]         Args: {:?}
[*]         User: {:?}
[*]       Domain: {:?}
[*] Created file: {:?}
",
		pid,
		process_path,
		&args[1..],
		username,
		domain,
		path
	);
	println!("{}", output);

	let mut file = File::create(path).unwrap();
	file.write_all(output.as_bytes()).unwrap();
}
