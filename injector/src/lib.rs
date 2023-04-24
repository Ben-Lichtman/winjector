#![feature(int_roundings)]

pub mod error;
pub mod helpers;
pub mod shellcode;
pub mod windows_wrapper;

use object::{read::pe::PeFile64, Object};
use windows::Win32::System::{
	Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE},
	Threading::THREAD_CREATE_RUN_IMMEDIATELY,
};

use crate::{
	error::{Error, Result},
	helpers::{get_module_by_file_name, redirect_main_thread, rva2offset},
	windows_wrapper::{process::Process, thread::Thread},
};
use std::ptr::null;

pub const BUFFER_SIZE: usize = 1024;

pub enum Technique {
	LoadLibraryA,
	ExportedLoader(String),
}

pub enum ControlFlow {
	NewThread,
	MainThread,
}

pub fn dll_inject(
	process: &Process,
	dll: &str,
	technique: Technique,
	control: ControlFlow,
) -> Result<()> {
	match technique {
		Technique::LoadLibraryA => dll_inject_loadlibrarya(process, dll, control)?,
		Technique::ExportedLoader(loader) => inject_with_loader(process, dll, loader, control)?,
	}

	Ok(())
}

fn dll_inject_loadlibrarya(process: &Process, dll: &str, control: ControlFlow) -> Result<()> {
	let function: usize = get_module_by_file_name(process, "KERNEL32.DLL")
		.find_map(|(_, m)| m.export_address("LoadLibraryA").ok())
		.ok_or(Error::InjectFailed)?;

	let allocated = process.virtual_alloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)?;
	allocated.write_memory(dll.as_bytes(), 0)?;

	let allocated_pos = allocated.address();

	match control {
		ControlFlow::NewThread => {
			Thread::spawn_remote(
				process,
				0,
				function,
				allocated_pos as _,
				THREAD_CREATE_RUN_IMMEDIATELY,
			)?;
		}
		ControlFlow::MainThread => unimplemented!(),
	}

	Ok(())
}

fn inject_with_loader(
	process: &Process,
	dll: &str,
	loader: String,
	control: ControlFlow,
) -> Result<()> {
	// read DLL
	let dll_raw = std::fs::read(dll)?;
	let dll = PeFile64::parse(dll_raw.as_slice())?;

	// Find loader function within
	let loader_export = dll
		.exports()
		.unwrap()
		.into_iter()
		.find(|e| e.name() == loader.as_bytes())
		.unwrap();
	let loader_addr_rva = loader_export.address() as _;

	// Translate to file offset
	let loader_addr_offset = rva2offset(&dll, loader_addr_rva).ok_or(Error::InjectFailed)?;

	// Allocate space in target process
	let space_to_allocate = dll_raw.len().next_multiple_of(0x1000);
	let allocated = process.virtual_alloc(
		0,
		space_to_allocate,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READ,
	)?;

	let entry_point = allocated.address() + loader_addr_offset;

	// Write DLL to allocated space
	allocated.write_memory(&dll_raw, 0).unwrap();

	match control {
		ControlFlow::NewThread => {
			Thread::spawn_remote(
				process,
				0,
				entry_point,
				null(),
				THREAD_CREATE_RUN_IMMEDIATELY,
			)?;
		}
		ControlFlow::MainThread => redirect_main_thread(process, entry_point)?,
	}

	Ok(())
}
