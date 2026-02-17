mod payloads;

use crate::payloads::*;
// use reloader as _;
use std::ffi::{CStr, c_void};
// use symfinder::find_symbol;

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
extern "system" fn DllMain(_dll_module: i64, call_reason: i32, _reserved: *const c_void) -> i32 {
	const DLL_PROCESS_ATTACH: i32 = 1;
	const DLL_PROCESS_DETACH: i32 = 0;

	match call_reason {
		DLL_PROCESS_ATTACH => attach(),
		DLL_PROCESS_DETACH => (),
		_ => (),
	}
	1
}

fn attach() {
	// network_payload();
	// write_file(&env::var("TMP").unwrap());
	// write_file("C:\\pwned");
	// experiment();
	message_box("hello world");
	// message_box(&format!("Found symbol at {symbol:x}"))
}
