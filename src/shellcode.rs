use hex::decode;

pub fn gen_function_call_ret_shellcode(
	function: u64,
	arg1: u64,
	arg2: u64,
	arg3: u64,
	arg4: u64,
) -> Vec<u8> {
	let shellcode = concat!(
		"9c",                   // pushfq
		"4157",                 // push r15
		"4156",                 // push r14
		"4155",                 // push r13
		"4154",                 // push r12
		"4153",                 // push r11
		"4152",                 // push r10
		"4151",                 // push r9
		"4150",                 // push r8
		"55",                   // push rbp
		"56",                   // push rsi
		"57",                   // push rdi
		"52",                   // push rdx
		"51",                   // push rcx
		"53",                   // push rbx
		"50",                   // push rax
		"48b9ffffffffffffffff", // mov rcx, {arg1}
		"48baffffffffffffffff", // mov rdx, {arg2}
		"49b8ffffffffffffffff", // mov r8, {arg3}
		"49b9ffffffffffffffff", // mov r9, {arg4}
		"48b8ffffffffffffffff", // mov rax, {function}
		"4883ec18",             // sub rsp, 0x18
		"ffd0",                 // call rax
		"4883c418",             // add rsp, 0x18
		"58",                   // pop rax
		"5b",                   // pop rbx
		"59",                   // pop rcx
		"5a",                   // pop rdx
		"5f",                   // pop rdi
		"5e",                   // pop rsi
		"5d",                   // pop rbp
		"4158",                 // pop r8
		"4159",                 // pop r9
		"415a",                 // pop r10
		"415b",                 // pop r11
		"415c",                 // pop r12
		"415d",                 // pop r13
		"415e",                 // pop r14
		"415f",                 // pop r15
		"9d",                   // popfq
		"c3",                   // ret
	);
	let mut bytes = decode(shellcode).unwrap();

	// Patch arguments
	bytes[0x1a..0x22].copy_from_slice(&arg1.to_le_bytes());
	bytes[0x24..0x2c].copy_from_slice(&arg2.to_le_bytes());
	bytes[0x2e..0x36].copy_from_slice(&arg3.to_le_bytes());
	bytes[0x38..0x40].copy_from_slice(&arg4.to_le_bytes());

	// Patch function
	bytes[0x42..0x4a].copy_from_slice(&function.to_le_bytes());

	// Add breakpoint for debugging
	// bytes.insert(0, 0xcc);

	bytes
}

pub fn gen_function_call_jump_shellcode(
	ret: u64,
	function: u64,
	arg1: u64,
	arg2: u64,
	arg3: u64,
	arg4: u64,
) -> Vec<u8> {
	let shellcode = concat!(
		"68ffffffff",           // push {dummy}
		"9c",                   // pushfq
		"4157",                 // push r15
		"4156",                 // push r14
		"4155",                 // push r13
		"4154",                 // push r12
		"4153",                 // push r11
		"4152",                 // push r10
		"4151",                 // push r9
		"4150",                 // push r8
		"55",                   // push rbp
		"56",                   // push rsi
		"57",                   // push rdi
		"52",                   // push rdx
		"51",                   // push rcx
		"53",                   // push rbx
		"50",                   // push rax
		"48b8ffffffffffffffff", // mov rax, {ret}
		"4889842480000000",     // mov [rsp + 0x80], rax
		"48b9ffffffffffffffff", // mov rcx, {arg1}
		"48baffffffffffffffff", // mov rdx, {arg2}
		"49b8ffffffffffffffff", // mov r8, {arg3}
		"49b9ffffffffffffffff", // mov r9, {arg4}
		"48b8ffffffffffffffff", // mov rax, {function}
		"4883ec10",             // sub rsp, 0x10
		"ffd0",                 // call rax
		"4883c410",             // add rsp, 0x10
		"58",                   // pop rax
		"5b",                   // pop rbx
		"59",                   // pop rcx
		"5a",                   // pop rdx
		"5f",                   // pop rdi
		"5e",                   // pop rsi
		"5d",                   // pop rbp
		"4158",                 // pop r8
		"4159",                 // pop r9
		"415a",                 // pop r10
		"415b",                 // pop r11
		"415c",                 // pop r12
		"415d",                 // pop r13
		"415e",                 // pop r14
		"415f",                 // pop r15
		"9d",                   // popfq
		"c3",                   // ret
	);
	let mut bytes = decode(shellcode).unwrap();

	// Patch return address
	bytes[0x1f..0x27].copy_from_slice(&ret.to_le_bytes());

	// Patch arguments
	bytes[0x31..0x39].copy_from_slice(&arg1.to_le_bytes());
	bytes[0x3b..0x43].copy_from_slice(&arg2.to_le_bytes());
	bytes[0x45..0x4d].copy_from_slice(&arg3.to_le_bytes());
	bytes[0x4f..0x57].copy_from_slice(&arg4.to_le_bytes());

	// Patch function
	bytes[0x59..0x61].copy_from_slice(&function.to_le_bytes());

	// Add breakpoint for debugging
	// bytes.insert(0, 0xcc);

	bytes
}
