use object::{
	pe::{
		ImageBaseRelocation, ImageDataDirectory, ImageDosHeader, ImageImportDescriptor,
		ImageNtHeaders64, ImageSectionHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC,
		IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64,
		IMAGE_REL_BASED_HIGHLOW,
	},
	pod::{from_bytes, from_bytes_mut, slice_from_bytes, slice_from_bytes_mut},
	LittleEndian, U16Bytes,
};
use std::{
	collections::HashMap,
	mem::size_of,
	ops::{Index, IndexMut, Range},
};

pub struct Pefile64<'a> {
	dos_header: &'a mut ImageDosHeader,
	nt_header: &'a mut ImageNtHeaders64,
	data_dir: &'a mut [ImageDataDirectory],
	section_headers: &'a mut [ImageSectionHeader],
	bytes: &'a mut [u8],
	bytes_offset: usize,
	rva_mappings: HashMap<usize, usize>,
}

impl<'a> Pefile64<'a> {
	pub fn new(bytes: &'a mut [u8]) -> Self {
		let mut bytes_offset = 0;

		// Parse DOS header
		let (dos_header, bytes) = from_bytes_mut::<ImageDosHeader>(bytes).unwrap();
		bytes_offset += size_of::<ImageDosHeader>();

		// Parse NT headers
		let nt_offset = dos_header.nt_headers_offset() as usize - bytes_offset;
		let (nt_header, bytes) =
			from_bytes_mut::<ImageNtHeaders64>(&mut bytes[nt_offset..]).unwrap();
		bytes_offset += nt_offset + size_of::<ImageNtHeaders64>();

		// Parse data directory
		let number_of_rva_and_sizes = nt_header
			.optional_header
			.number_of_rva_and_sizes
			.get(LittleEndian) as usize;
		let (data_dir, bytes) =
			slice_from_bytes_mut::<ImageDataDirectory>(bytes, number_of_rva_and_sizes).unwrap();
		bytes_offset += number_of_rva_and_sizes * size_of::<ImageDataDirectory>();

		// Parse section headers
		let number_of_sections =
			nt_header.file_header.number_of_sections.get(LittleEndian) as usize;
		let (section_headers, bytes) =
			slice_from_bytes_mut::<ImageSectionHeader>(bytes, number_of_sections).unwrap();
		bytes_offset += number_of_sections * size_of::<ImageSectionHeader>();

		// Create mappings from RVA to address on file
		let rva_mappings = section_headers
			.iter()
			.flat_map(|header| {
				let vaddr = header.virtual_address.get(LittleEndian);
				let file_addr = header.pointer_to_raw_data.get(LittleEndian);
				let file_size = header.size_of_raw_data.get(LittleEndian);
				(0..file_size)
					.step_by(0x1000)
					.map(move |offset| ((vaddr + offset) as usize, (file_addr + offset) as usize))
			})
			.collect::<HashMap<_, _>>();

		Self {
			dos_header,
			nt_header,
			data_dir,
			section_headers,
			bytes,
			bytes_offset,
			rva_mappings,
		}
	}

	pub fn dos_header(&self) -> &ImageDosHeader { self.dos_header }

	pub fn dos_header_mut(&mut self) -> &mut ImageDosHeader { self.dos_header }

	pub fn nt_header(&self) -> &ImageNtHeaders64 { self.nt_header }

	pub fn nt_header_mut(&mut self) -> &mut ImageNtHeaders64 { self.nt_header }

	pub fn data_dir(&self) -> &[ImageDataDirectory] { self.data_dir }

	pub fn data_dir_mut(&mut self) -> &mut [ImageDataDirectory] { self.data_dir }

	pub fn section_headers(&self) -> &[ImageSectionHeader] { self.section_headers }

	pub fn section_headers_mut(&mut self) -> &mut [ImageSectionHeader] { self.section_headers }

	pub fn rva_to_file_offset(&self, rva: usize) -> usize { self.rva_mappings[&rva] }

	pub fn relocations(&self) -> Vec<(ImageBaseRelocation, Vec<(u8, u16)>)> {
		let mut relocations = Vec::new();
		let dd_reloc = self.data_dir[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		let reloc_section_header = self
			.section_headers
			.iter()
			.find(|header| header.virtual_address == dd_reloc.virtual_address)
			.unwrap();
		let start = reloc_section_header.pointer_to_raw_data.get(LittleEndian) as usize;
		let size = reloc_section_header.size_of_raw_data.get(LittleEndian) as usize;
		let mut reloc_raw_data = &self[start..start + size];
		while !reloc_raw_data.is_empty() {
			let (block_header, remaining) =
				from_bytes::<ImageBaseRelocation>(reloc_raw_data).unwrap();
			let block_size = block_header.size_of_block.get(LittleEndian) as usize;
			if block_size == 0 {
				break;
			}
			let num_blocks = (block_size - size_of::<ImageBaseRelocation>()) / 2;
			let (block_relocations, remaining) =
				slice_from_bytes::<U16Bytes<LittleEndian>>(remaining, num_blocks).unwrap();
			let block_relocations = block_relocations
				.iter()
				.map(|bytes| {
					let as_num = bytes.get(LittleEndian);
					let reloc_type = (as_num >> 0xc) as u8;
					let reloc_offset = as_num & 0xfff;
					(reloc_type, reloc_offset)
				})
				.collect::<Vec<_>>();
			relocations.push((block_header.clone(), block_relocations));
			reloc_raw_data = remaining;
		}
		relocations
	}

	pub fn apply_relocations(
		&mut self,
		relocations: Vec<(ImageBaseRelocation, Vec<(u8, u16)>)>,
		reloc_delta: i64,
	) {
		relocations
			.into_iter()
			.for_each(|(block_header, block_relocations)| {
				block_relocations
					.into_iter()
					.for_each(|(reloc_type, reloc_offset)| {
						// Convert page to file offset
						let file_offset = self.rva_to_file_offset(
							block_header.virtual_address.get(LittleEndian) as usize,
						);
						let file_offset = file_offset + reloc_offset as usize;

						// Perform the relocation
						match reloc_type as _ {
							IMAGE_REL_BASED_ABSOLUTE => (),
							IMAGE_REL_BASED_HIGHLOW => {
								let target = &mut self[file_offset..file_offset + 4];
								let mut old_bytes = [0u8; 4];
								old_bytes.copy_from_slice(target);
								let new_val = i32::from_le_bytes(old_bytes) + reloc_delta as i32;
								target.copy_from_slice(&new_val.to_le_bytes());
							}
							IMAGE_REL_BASED_DIR64 => {
								let target = &mut self[file_offset..file_offset + 8];
								let mut old_bytes = [0u8; 8];
								old_bytes.copy_from_slice(target);
								let new_val = i64::from_le_bytes(old_bytes) + reloc_delta as i64;
								target.copy_from_slice(&new_val.to_le_bytes());
							}
							_ => panic!("Unknown relocation type"),
						}
					})
			});
	}
}

impl<'a> Index<Range<usize>> for Pefile64<'a> {
	type Output = [u8];

	fn index(&self, index: Range<usize>) -> &Self::Output {
		let start = index.start - self.bytes_offset;
		let end = index.end - self.bytes_offset;
		&self.bytes[start..end]
	}
}

impl<'a> IndexMut<Range<usize>> for Pefile64<'a> {
	fn index_mut(&mut self, index: Range<usize>) -> &mut Self::Output {
		let start = index.start - self.bytes_offset;
		let end = index.end - self.bytes_offset;
		&mut self.bytes[start..end]
	}
}
