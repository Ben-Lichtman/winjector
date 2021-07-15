pub mod bindings {
	windows::include_bindings!();

	pub use Windows::{
		System::ProcessorArchitecture,
		Win32::{
			Foundation::{
				CloseHandle, BOOL, FILETIME, HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, PSTR, WPARAM,
			},
			System::{
				Diagnostics::{
					Debug::{
						FlushInstructionCache, GetThreadContext, InitializeContext,
						ReadProcessMemory, SetThreadContext, WriteProcessMemory, CONTEXT,
					},
					ToolHelp::{
						CreateToolhelp32Snapshot, Thread32First, Thread32Next,
						Toolhelp32ReadProcessMemory, CREATE_TOOLHELP_SNAPSHOT_FLAGS,
						TH32CS_INHERIT, TH32CS_SNAPALL, TH32CS_SNAPHEAPLIST, TH32CS_SNAPMODULE,
						TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
					},
				},
				LibraryLoader::GetProcAddress,
				Memory::{
					VirtualAlloc2, VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, VirtualQueryEx,
					MEM_COMMIT, MEM_LARGE_PAGES, MEM_RELEASE, MEM_RESERVE, MEM_RESET,
					MEM_RESET_UNDO, PAGE_ENCLAVE_DECOMMIT, PAGE_ENCLAVE_MASK,
					PAGE_ENCLAVE_SS_FIRST, PAGE_ENCLAVE_SS_REST, PAGE_ENCLAVE_THREAD_CONTROL,
					PAGE_ENCLAVE_UNVALIDATED, PAGE_EXECUTE, PAGE_EXECUTE_READ,
					PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GRAPHICS_COHERENT,
					PAGE_GRAPHICS_EXECUTE, PAGE_GRAPHICS_EXECUTE_READ,
					PAGE_GRAPHICS_EXECUTE_READWRITE, PAGE_GRAPHICS_NOACCESS, PAGE_GRAPHICS_NOCACHE,
					PAGE_GRAPHICS_READONLY, PAGE_GRAPHICS_READWRITE, PAGE_GUARD, PAGE_NOACCESS,
					PAGE_NOCACHE, PAGE_READONLY, PAGE_READWRITE, PAGE_REVERT_TO_FILE_MAP,
					PAGE_TARGETS_INVALID, PAGE_TARGETS_NO_UPDATE, PAGE_TYPE, PAGE_WRITECOMBINE,
					PAGE_WRITECOPY, SEC_64K_PAGES, SEC_COMMIT, SEC_FILE, SEC_IMAGE,
					SEC_IMAGE_NO_EXECUTE, SEC_LARGE_PAGES, SEC_NOCACHE, SEC_PARTITION_OWNER_HANDLE,
					SEC_PROTECTED_IMAGE, SEC_RESERVE, SEC_WRITECOMBINE, VIRTUAL_ALLOCATION_TYPE,
					VIRTUAL_FREE_TYPE,
				},
				ProcessStatus::{
					K32EnumProcessModulesEx, K32EnumProcesses, K32GetModuleBaseNameA,
					K32GetModuleFileNameExA, K32GetModuleInformation, LIST_MODULES_32BIT,
					LIST_MODULES_64BIT, LIST_MODULES_DEFAULT, MODULEINFO,
				},
				SystemInformation::{GetSystemInfo, SYSTEM_INFO},
				SystemServices::{LPTHREAD_START_ROUTINE, MEMORY_BASIC_INFORMATION},
				Threading::{
					CreateRemoteThreadEx, GetCurrentProcess, GetExitCodeThread, GetProcessId,
					GetThreadTimes, InitializeProcThreadAttributeList, OpenProcess, OpenThread,
					ResumeThread, SuspendThread, WaitForSingleObjectEx,
					LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_ACCESS_RIGHTS, PROCESS_ALL_ACCESS,
					PROCESS_CREATE_PROCESS, PROCESS_CREATE_THREAD, PROCESS_DELETE,
					PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION,
					PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_READ_CONTROL,
					PROCESS_SET_INFORMATION, PROCESS_SET_QUOTA, PROCESS_SUSPEND_RESUME,
					PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, PROCESS_VM_OPERATION, PROCESS_VM_READ,
					PROCESS_VM_WRITE, PROCESS_WRITE_DAC, PROCESS_WRITE_OWNER,
					THREAD_CREATE_RUN_IMMEDIATELY, THREAD_CREATE_SUSPENDED, THREAD_CREATION_FLAGS,
					WAIT_FAILED, WAIT_RETURN_CAUSE,
				},
			},
			UI::WindowsAndMessaging::{
				EnumChildWindows, EnumThreadWindows, GetClassNameA, GetWindowTextA, SendMessageA,
				WNDENUMPROC,
			},
		},
	};
}

pub mod error;
pub mod helpers;
pub mod loader;
pub mod object;
pub mod shellcode;
pub mod windows_wrapper;

pub const BUFFER_SIZE: usize = 1024;
