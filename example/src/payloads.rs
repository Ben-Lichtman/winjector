use std::{
	arch::asm,
	env,
	fs::{self, File},
	io::Write,
	net::{Ipv4Addr, SocketAddrV4, TcpStream},
};

use windows::{
	Win32::{
		Foundation::HANDLE,
		System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx},
		UI::WindowsAndMessaging::{MB_OK, MessageBoxA},
	},
	core::PCSTR,
};

pub fn write_file(path: &str) {
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

pub fn network_payload() {
	let socket = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 42069);
	// unsafe { asm!("int3") };
	match TcpStream::connect(socket) {
		Ok(mut s) => {
			write!(&mut s, "Hello world!\r\n").unwrap();
		}
		Err(e) => {
			let error = format!("{:?}", e);
			std::fs::write("C:\\pwned\\output.txt", error).unwrap();
		}
	};
}

pub fn message_box(msg: &str) {
	let mut bytes = Vec::from(msg);
	bytes.push(0);
	unsafe { MessageBoxA(None, PCSTR(bytes.as_ptr()), PCSTR(bytes.as_ptr()), MB_OK) };
}

// ws2_32!WSASocketW
// mswsock!SockSetHandleContext

pub fn experiment() {
	let output = unsafe {
		VirtualAllocEx(
			HANDLE(-1 as _),
			None,
			0x1000,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE,
		)
	};

	// unsafe { asm!("int3") };
}
