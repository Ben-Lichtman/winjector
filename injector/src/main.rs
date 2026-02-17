use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;
use winjector::{dll_inject, helpers::get_process_by_file_name};

#[derive(Debug, Parser)]
pub struct Cli {
	#[arg(short, long)]
	dll: PathBuf,
	#[command(flatten)]
	process: Process,
	#[command(flatten)]
	technique: Technique,
	#[arg(value_enum)]
	control_flow: ControlFlow,
}

#[derive(Debug, Parser)]
#[group(required = true, multiple = false)]
pub struct Process {
	#[arg(short, long)]
	pid: Option<u32>,
	#[arg(short, long)]
	name: Option<String>,
}

#[derive(Debug, Parser)]
#[group(required = true, multiple = false)]
pub struct Technique {
	#[arg(short, long)]
	load_library: bool,
	#[arg(short, long)]
	exported_loader: Option<String>,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum ControlFlow {
	NewThread,
	MainThread,
}

fn process_from_name(target_name: &str) -> winjector::windows_wrapper::process::Process {
	// Find target process
	let mut targets = get_process_by_file_name(target_name).collect::<Vec<_>>();
	if targets.is_empty() {
		panic!("process not found");
	}
	// if targets.len() != 1 {
	// 	panic!("multiple processes found");
	// }
	let (target_path, target) = targets.swap_remove(0);
	let target_pid = target.pid().unwrap();
	// println!("=> Found PID: {}, path: {}", target_pid, target_path);
	target
}

fn process_from_pid(pid: u32) -> winjector::windows_wrapper::process::Process {
	// println!("=> Found PID: {}", pid);
	winjector::windows_wrapper::process::Process::from_pid(pid, PROCESS_ALL_ACCESS, true).unwrap()
}

fn main() {
	let cli = Cli::parse();

	let dll = cli.dll.to_str().unwrap();

	let process = match cli.process {
		Process {
			pid: Some(pid),
			name: None,
		} => process_from_pid(pid),
		Process {
			pid: None,
			name: Some(name),
		} => process_from_name(&name),
		_ => panic!(),
	};

	let technique = match cli.technique {
		Technique {
			load_library: true,
			exported_loader: None,
		} => winjector::Technique::LoadLibraryA,
		Technique {
			load_library: false,
			exported_loader: Some(loader),
		} => winjector::Technique::ExportedLoader(loader),
		_ => panic!(),
	};

	let control_flow = match cli.control_flow {
		ControlFlow::NewThread => winjector::ControlFlow::NewThread,
		ControlFlow::MainThread => winjector::ControlFlow::MainThread,
	};

	dll_inject(&process, dll, technique, control_flow).unwrap();
}
