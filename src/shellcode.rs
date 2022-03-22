use crate::error::Result;
use iced_x86::code_asm::*;

const DEBUG_INTERRUPT: bool = true;

pub fn shellode_fn_call(
	function: u64,
	arg1: u64,
	arg2: u64,
	arg3: u64,
	arg4: u64,
) -> Result<Vec<u8>> {
	let mut a = CodeAssembler::new(64)?;

	if DEBUG_INTERRUPT {
		a.int3()?;
	}

	// Save state
	a.pushfq()?;
	a.push(r15)?;
	a.push(r14)?;
	a.push(r13)?;
	a.push(r12)?;
	a.push(r11)?;
	a.push(r10)?;
	a.push(r9)?;
	a.push(r8)?;
	a.push(rbp)?;
	a.push(rsi)?;
	a.push(rdi)?;
	a.push(rdx)?;
	a.push(rcx)?;
	a.push(rbx)?;
	a.push(rax)?;

	// Call function
	a.mov(rcx, arg1)?;
	a.mov(rdx, arg2)?;
	a.mov(r8, arg3)?;
	a.mov(r9, arg4)?;
	a.mov(rax, function)?;
	a.call(rax)?;

	// Restore state
	a.pop(rax)?;
	a.pop(rbx)?;
	a.pop(rcx)?;
	a.pop(rdx)?;
	a.pop(rdi)?;
	a.pop(rsi)?;
	a.pop(rbp)?;
	a.push(r8)?;
	a.push(r9)?;
	a.push(r10)?;
	a.push(r11)?;
	a.push(r12)?;
	a.push(r13)?;
	a.push(r14)?;
	a.pop(r15)?;
	a.popfq()?;

	a.ret()?;

	let output = a.assemble(0x0)?;
	Ok(output)
}
