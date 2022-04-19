pub type Result<T> = core::result::Result<T, Error>;

#[repr(u16)]
pub enum Error {
	SelfFind,
	ModuleByHash,
	ModuleByAscii,
	ExportVaByHash,
	ExportVaByAscii,
	PeHeaders,
	ExportTable,
	ImportTable,
	Allocation,
	Protect,
	Flush,
	LoadLibrary,
	RelocationType,
	SplitString,
	ParseNumber,
	SyscallNumber,
}
