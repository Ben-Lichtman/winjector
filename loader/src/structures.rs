use core::{mem::size_of, slice};
use cstr_core::CStr;
use object::{
	pe::{
		ImageDataDirectory, ImageDosHeader, ImageExportDirectory, ImageImportDescriptor,
		ImageNtHeaders64, ImageSectionHeader, IMAGE_DIRECTORY_ENTRY_EXPORT,
		IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
	},
	read::pe::{ImageNtHeaders, ImageOptionalHeader},
	LittleEndian,
};

pub struct PeHeaders {
	pub dos_header: &'static mut ImageDosHeader,
	pub nt_header: &'static mut ImageNtHeaders64,
	pub data_directories: &'static mut [ImageDataDirectory],
	pub section_headers: &'static mut [ImageSectionHeader],
}

impl PeHeaders {
	pub fn parse(address: *mut u8) -> Option<Self> {
		let dos_header_ptr = address;
		let dos_header = unsafe { &mut *dos_header_ptr.cast::<ImageDosHeader>() };
		if dos_header.e_magic.get(LittleEndian) != IMAGE_DOS_SIGNATURE {
			return None;
		}
		let nt_header_offset = dos_header.nt_headers_offset() as usize;
		// Sanity check
		if nt_header_offset > 1024 {
			return None;
		}
		let nt_header_ptr = address.wrapping_add(nt_header_offset);
		let nt_header = unsafe { &mut *nt_header_ptr.cast::<ImageNtHeaders64>() };
		if nt_header.signature.get(LittleEndian) != IMAGE_NT_SIGNATURE {
			return None;
		}
		if !nt_header.is_valid_optional_magic() {
			return None;
		}
		let data_directories_ptr = nt_header_ptr.wrapping_add(size_of::<ImageNtHeaders64>());
		let num_data_directories = nt_header.optional_header().number_of_rva_and_sizes() as _;
		let data_directories = unsafe {
			slice::from_raw_parts_mut(
				data_directories_ptr.cast::<ImageDataDirectory>(),
				num_data_directories,
			)
		};
		let section_headers_ptr = data_directories_ptr
			.wrapping_add(num_data_directories * size_of::<ImageDataDirectory>());
		let num_section_headers = nt_header.file_header().number_of_sections.get(LittleEndian) as _;
		let section_headers = unsafe {
			slice::from_raw_parts_mut(
				section_headers_ptr.cast::<ImageSectionHeader>(),
				num_section_headers,
			)
		};

		Some(Self {
			dos_header,
			nt_header,
			data_directories,
			section_headers,
		})
	}

	pub fn export_table_mem(&self, image_base: *mut u8) -> Option<ExportTable> {
		let export_table_data_dir = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_EXPORT)?;
		let export_table_rva = export_table_data_dir.virtual_address.get(LittleEndian);
		let export_table_ptr = image_base.wrapping_add(export_table_rva as _);
		Some(ExportTable::parse(export_table_ptr, export_table_rva as _))
	}

	pub fn import_table_mem(&self, image_base: *mut u8) -> Option<ImportTable> {
		let import_table_data_dir = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_IMPORT)?;
		let import_table_rva = import_table_data_dir.virtual_address.get(LittleEndian);
		let import_table_size = import_table_data_dir.size.get(LittleEndian);
		let import_table_ptr = image_base.wrapping_add(import_table_rva as _);
		Some(ImportTable::parse(import_table_ptr, import_table_size as _))
	}
}

pub struct ExportTable {
	pub export_directory: &'static mut ImageExportDirectory,
	pub address_table: &'static mut [u32],
	pub name_table: &'static mut [u32],
	pub ordinal_table: &'static mut [u16],
}

impl ExportTable {
	pub fn parse(address: *mut u8, rva: usize) -> Self {
		let export_directory_ptr = address;
		let export_directory = unsafe { &mut *export_directory_ptr.cast::<ImageExportDirectory>() };

		let address_table_ptr = address
			.wrapping_add(export_directory.address_of_functions.get(LittleEndian) as _)
			.wrapping_sub(rva)
			.cast::<u32>();
		let address_table_len = export_directory.number_of_functions.get(LittleEndian) as _;
		let address_table =
			unsafe { slice::from_raw_parts_mut(address_table_ptr, address_table_len) };

		let name_table_ptr = address
			.wrapping_add(export_directory.address_of_names.get(LittleEndian) as _)
			.wrapping_sub(rva)
			.cast::<u32>();
		let name_table_len = export_directory.number_of_names.get(LittleEndian) as _;
		let name_table = unsafe { slice::from_raw_parts_mut(name_table_ptr, name_table_len) };

		let ordinal_table_ptr = address
			.wrapping_add(export_directory.address_of_name_ordinals.get(LittleEndian) as _)
			.wrapping_sub(rva)
			.cast::<u16>();
		let ordinal_table_len = export_directory.number_of_names.get(LittleEndian) as _;
		let ordinal_table =
			unsafe { slice::from_raw_parts_mut(ordinal_table_ptr, ordinal_table_len) };

		Self {
			export_directory,
			address_table,
			name_table,
			ordinal_table,
		}
	}

	pub fn iter_name_ord(&self) -> impl Iterator<Item = (u32, u16)> + '_ {
		self.name_table
			.iter()
			.copied()
			.zip(self.ordinal_table.iter().copied())
	}

	pub fn iter_string_addr(&self, image_base: *mut u8) -> impl Iterator<Item = (&CStr, *mut u8)> {
		self.iter_name_ord().map(move |(name_rva, ord)| {
			let string_ptr = image_base.wrapping_add(name_rva as _);
			let string = unsafe { CStr::from_ptr(string_ptr as _) };
			let address_rva = unsafe { *self.address_table.get_unchecked(ord as usize) };
			let address = image_base.wrapping_add(address_rva as _);
			(string, address)
		})
	}
}

pub struct ImportTable {
	pub import_descriptors: &'static mut [ImageImportDescriptor],
}

impl ImportTable {
	pub fn parse(address: *mut u8, size: usize) -> Self {
		let number_of_entries = size / size_of::<ImageImportDescriptor>() - 1;
		let import_descriptor_ptr = address.cast::<ImageImportDescriptor>();
		let import_descriptors =
			unsafe { slice::from_raw_parts_mut(import_descriptor_ptr, number_of_entries) };

		Self { import_descriptors }
	}
}