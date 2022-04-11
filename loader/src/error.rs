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
	VirtualAlloc,
	LoadLibrary,
	RelocEntry,
	RelocationType,
	SplitString,
	ParseNumber,
}
