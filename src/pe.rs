use anyhow::{Context, Result};
use log::{debug, info, warn};
use std::mem;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::ProcessStatus::{
    K32EnumProcessModules, K32GetModuleInformation, MODULEINFO,
};
use windows::Win32::Foundation::HMODULE;
use std::thread;
use std::time::Duration;
use windows::Win32::System::Memory::VirtualProtectEx;
use windows::Win32::System::Memory::PAGE_EXECUTE_READ;
use windows::Win32::System::Memory::PAGE_READONLY;
use windows::Win32::System::Memory::PAGE_READWRITE;
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS;
use windows::Win32::System::Memory::VirtualQueryEx;
use windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION;
use windows::Win32::System::Memory::MEM_COMMIT;
use windows::Win32::System::Memory::PAGE_NOACCESS;

const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const MAX_SECTION_SIZE: usize = 0x40000000;
const MAX_IMAGE_SIZE: usize = 0x80000000;
const VALID_SECTION_CHARS: &[u8] = b"._-$@0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#[derive(Debug, Clone)]
pub struct Section {
    pub address: usize,
    pub size: usize,
    #[allow(dead_code)]
    pub characteristics: u32,
    #[allow(dead_code)]
    pub name: String,
}

#[allow(dead_code)]
impl Section {
    pub fn is_executable(&self) -> bool {
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    pub fn is_valid_size(&self) -> bool {
        if self.size > MAX_SECTION_SIZE {
            return false;
        }

        if self.size > 0x1000 && self.size & 0xFFF != 0 && self.size & 0xFFF < 0x800 {
            return false;
        }

        true
    }

    pub fn has_valid_name(&self, name: &[u8]) -> bool {
        let valid_chars = name.iter()
            .filter(|&&c| VALID_SECTION_CHARS.contains(&c) || c == 0)
            .count();
            
        if name.len() <= 8 {
            return valid_chars > 0;
        }

        valid_chars >= name.len() / 4
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageDosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageOptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageSectionHeader {
    name: [u8; 8],
    misc: u32, 
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ImageImportDescriptor {
    original_first_thunk: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
}

pub struct PEImage {
    base_address: usize,
    process_handle: HANDLE,
    _dos_header: ImageDosHeader, 
    nt_headers: ImageNtHeaders64,
    sections: Vec<Section>,
}

impl PEImage {
    pub fn from_process(process_handle: HANDLE) -> Result<Self> {
        let base_address = Self::find_base_address(process_handle)?;
        
        
        let dos_header = Self::read_dos_header(process_handle, base_address)?;
        
        if dos_header.e_magic != 0x5A4D {
            anyhow::bail!("Invalid DOS signature");
        }

        
        if dos_header.e_lfanew <= 0 || dos_header.e_lfanew > 0x1000 {
            anyhow::bail!("Invalid e_lfanew value: {}", dos_header.e_lfanew);
        }

        let nt_headers = Self::read_nt_headers(
            process_handle,
            base_address + dos_header.e_lfanew as usize,
        )?;

        if nt_headers.signature != 0x4550 {
            anyhow::bail!("Invalid NT signature");
        }

        
        if nt_headers.optional_header.size_of_image as usize > MAX_IMAGE_SIZE {
            anyhow::bail!("Image size too large: {}", nt_headers.optional_header.size_of_image);
        }

        let sections = Self::read_sections(
            process_handle,
            base_address,
            &nt_headers,
        )?;

        Ok(Self {
            base_address,
            process_handle,
            _dos_header: dos_header,
            nt_headers,
            sections,
        })
    }

    pub fn base_address(&self) -> usize {
        self.base_address
    }

    pub fn sections(&self) -> Result<Vec<Section>> {
        Ok(self.sections.clone())
    }

    pub fn resolve_imports(&self) -> Result<()> {
        let import_dir = &self.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if import_dir.virtual_address == 0 {
            debug!("No import directory found");
            return Ok(());
        }

        let import_descriptor_addr = self.base_address + import_dir.virtual_address as usize;
        let mut current_desc_addr = import_descriptor_addr;
        let mut retry_count = 0;
        let mut total_retries = 0;

        loop {
            if total_retries > 50 {
                return Err(anyhow::anyhow!("Too many total retries reading import descriptors"));
            }

            let mut desc: Option<ImageImportDescriptor> = None;
            let mut buffer = vec![0u8; mem::size_of::<ImageImportDescriptor>()];
            let mut total_read = 0;

            
            for chunk_size in [
                mem::size_of::<ImageImportDescriptor>(),
                0x10,
                0x8,
                0x4,
                0x2,
            ] {
                let remaining = mem::size_of::<ImageImportDescriptor>() - total_read;
                let current_chunk = remaining.min(chunk_size);

                
                for &protection in &[
                    PAGE_EXECUTE_READ,
                    PAGE_READONLY,
                    PAGE_READWRITE,
                    PAGE_EXECUTE_READWRITE,
                ] {
                    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                    let mut bytes_read = 0;

                    
                    let protect_result = unsafe {
                        VirtualProtectEx(
                            self.process_handle,
                            (current_desc_addr + total_read) as _,
                            current_chunk,
                            protection,
                            &mut old_protect,
                        )
                    };

                    if protect_result.is_ok() {
                        let read_result = unsafe {
                            ReadProcessMemory(
                                self.process_handle,
                                (current_desc_addr + total_read) as _,
                                buffer.as_mut_ptr().add(total_read) as _,
                                current_chunk,
                                Some(&mut bytes_read),
                            )
                        };

                        
                        unsafe {
                            let _ = VirtualProtectEx(
                                self.process_handle,
                                (current_desc_addr + total_read) as _,
                                current_chunk,
                                old_protect,
                                &mut old_protect,
                            );
                        }

                        if read_result.is_ok() && bytes_read > 0 {
                            total_read += bytes_read;
                            if total_read >= mem::size_of::<ImageImportDescriptor>() {
                                desc = Some(unsafe {
                                    std::ptr::read_unaligned(buffer.as_ptr() as *const _)
                                });
                                break;
                            }
                        }
                    }
                    thread::sleep(Duration::from_millis(10));
                }

                if total_read >= mem::size_of::<ImageImportDescriptor>() {
                    break;
                }
            }

            let desc = match desc {
                Some(d) => d,
                None => {
                    retry_count += 1;
                    total_retries += 1;
                    if retry_count > 3 {
                        
                        current_desc_addr += mem::size_of::<ImageImportDescriptor>();
                        retry_count = 0;
                        continue;
                    }
                    thread::sleep(Duration::from_millis(50 * (1 << retry_count.min(3))));
                    continue;
                }
            };

            if desc.first_thunk == 0 && desc.original_first_thunk == 0 {
                break;
            }

            
            let mut dll_name = String::new();
            let name_addr = self.base_address + desc.name as usize;
            let mut name_retry_count = 0;
            
            'name_retry: for _ in 0..5 {
                for chunk_size in [0x100, 0x40, 0x20, 0x10, 0x8] {
                    for &protection in &[PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE] {
                        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                        
                        if unsafe {
                            VirtualProtectEx(
                                self.process_handle,
                                name_addr as _,
                                chunk_size,
                                protection,
                                &mut old_protect,
                            )
                        }.is_ok() {
                            if let Ok(name) = self.read_string_with_size(name_addr, chunk_size) {
                                if !name.is_empty() {
                                    dll_name = name;
                                    break 'name_retry;
                                }
                            }

                            
                            unsafe {
                                let _ = VirtualProtectEx(
                                    self.process_handle,
                                    name_addr as _,
                                    chunk_size,
                                    old_protect,
                                    &mut old_protect,
                                );
                            }
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                }
                name_retry_count += 1;
                thread::sleep(Duration::from_millis(50 * (1 << name_retry_count.min(3))));
            }

            if dll_name.is_empty() {
                warn!("Failed to read DLL name at {:x}, skipping", name_addr);
                current_desc_addr += mem::size_of::<ImageImportDescriptor>();
                continue;
            }

            info!("Processing imports from: {}", dll_name);
            current_desc_addr += mem::size_of::<ImageImportDescriptor>();
        }

        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let size = self.nt_headers.optional_header.size_of_image as usize;
        if size > MAX_IMAGE_SIZE {
            anyhow::bail!("Image size too large: {}", size);
        }

        let mut buffer = vec![0u8; size];

        unsafe {
            std::ptr::write_unaligned(
                buffer.as_mut_ptr() as *mut ImageDosHeader,
                self._dos_header,
            );
        }

        
        let nt_headers_offset = self._dos_header.e_lfanew as usize;
        let nt_headers_size = mem::size_of::<ImageNtHeaders64>();
        unsafe {
            std::ptr::write_unaligned(
                buffer[nt_headers_offset..].as_mut_ptr() as *mut ImageNtHeaders64,
                self.nt_headers,
            );
        }

        
        let first_section_offset = nt_headers_offset + nt_headers_size;
        for (i, section) in self.sections.iter().enumerate() {
            let section_header = ImageSectionHeader {
                name: *b".text\0\0\0", 
                misc: section.size as u32,
                virtual_address: (section.address - self.base_address) as u32,
                size_of_raw_data: section.size as u32,
                pointer_to_raw_data: (section.address - self.base_address) as u32,
                pointer_to_relocations: 0,
                pointer_to_linenumbers: 0,
                number_of_relocations: 0,
                number_of_linenumbers: 0,
                characteristics: section.characteristics,
            };

            
            if !section.name.is_empty() && section.name.len() <= 8 {
                let mut name_bytes = [0u8; 8];
                name_bytes[..section.name.len()].copy_from_slice(section.name.as_bytes());
                unsafe {
                    std::ptr::write_unaligned(
                        &mut name_bytes as *mut [u8; 8],
                        name_bytes,
                    );
                }
            }

            let section_header_offset = first_section_offset + i * mem::size_of::<ImageSectionHeader>();
            unsafe {
                std::ptr::write_unaligned(
                    buffer[section_header_offset..].as_mut_ptr() as *mut ImageSectionHeader,
                    section_header,
                );
            }
        }

        
        for section in &self.sections {
            let offset = section.address - self.base_address;
            if offset + section.size > size {
                warn!("Section at {:x} extends beyond image size, truncating", section.address);
                continue;
            }
            
            
            if section.characteristics & 0x20000000 != 0 { 
                
                for i in 0..section.size {
                    if offset + i < size {
                        buffer[offset + i] = 0x90;
                    }
                }

                let pages = (section.size + 0xFFF) / 0x1000;
                let mut pages_read = std::collections::HashSet::new();

                while pages_read.len() < pages {
                    for page in 0..pages {
                        if pages_read.contains(&page) {
                            continue;
                        }

                        let page_addr = section.address + (page * 0x1000);
                        let mut mbi = MEMORY_BASIC_INFORMATION::default();

                        if unsafe {
                            VirtualQueryEx(
                                self.process_handle,
                                Some(page_addr as *const _),
                                &mut mbi,
                                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                            )
                        } == 0 {
                            continue;
                        }

                        
                        if mbi.State != MEM_COMMIT || mbi.Protect & PAGE_NOACCESS == PAGE_NOACCESS {
                            continue;
                        }

                        let mut page_buffer = vec![0u8; 0x1000];
                        let mut bytes_read = 0;

                        if unsafe {
                            ReadProcessMemory(
                                self.process_handle,
                                page_addr as _,
                                page_buffer.as_mut_ptr() as _,
                                0x1000,
                                Some(&mut bytes_read),
                            )
                        }.is_ok() && bytes_read > 0 {
                            let page_offset = offset + (page * 0x1000);
                            if page_offset + bytes_read <= size {
                                buffer[page_offset..page_offset + bytes_read].copy_from_slice(&page_buffer[..bytes_read]);
                                pages_read.insert(page);
                            }
                        }

                        thread::sleep(Duration::from_millis(10));
                    }
                }
            } else {
                
                let mut section_buffer = vec![0u8; section.size];
                let mut bytes_read = 0;

                if unsafe {
                    ReadProcessMemory(
                        self.process_handle,
                        section.address as _,
                        section_buffer.as_mut_ptr() as _,
                        section.size,
                        Some(&mut bytes_read),
                    )
                }.is_ok() && bytes_read > 0 && offset + bytes_read <= size {
                    buffer[offset..offset + bytes_read].copy_from_slice(&section_buffer[..bytes_read]);
                } else {
                    warn!("Failed to read section at {:x}, filling with zeros", section.address);
                    for i in 0..section.size {
                        if offset + i < size {
                            buffer[offset + i] = 0;
                        }
                    }
                }
            }
        }

        info!("Memory read complete: {} total bytes", buffer.len());
        Ok(buffer)
    }

    fn find_base_address(process_handle: HANDLE) -> Result<usize> {
        let mut module_handles = [HMODULE::default(); 1024];
        let mut bytes_needed = 0;

        unsafe {
            K32EnumProcessModules(
                process_handle,
                module_handles.as_mut_ptr(),
                std::mem::size_of_val(&module_handles) as u32,
                &mut bytes_needed,
            )
            .ok()
            .context("Failed to enumerate process modules")?;
        }

        
        let main_module = module_handles[0];
        let mut module_info = MODULEINFO::default();

        unsafe {
            K32GetModuleInformation(
                process_handle,
                main_module,
                &mut module_info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
            .ok()
            .context("Failed to get module information")?;
        }

        Ok(module_info.lpBaseOfDll as usize)
    }

    fn read_dos_header(process_handle: HANDLE, address: usize) -> Result<ImageDosHeader> {
        let mut buffer = vec![0u8; mem::size_of::<ImageDosHeader>()];
        let mut total_read = 0;
        let mut retry_count = 0;

        
        let chunk_sizes = [
            mem::size_of::<ImageDosHeader>(),
            0x40,
            0x20,
            0x10,
            0x8,
            0x4,
            0x2,
        ];

        while total_read < mem::size_of::<ImageDosHeader>() && retry_count < 10 {
            for &chunk_size in &chunk_sizes {
                let remaining = mem::size_of::<ImageDosHeader>() - total_read;
                let current_chunk = remaining.min(chunk_size);
                let mut bytes_read = 0;

                
                for &protection in &[PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE] {
                    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                    
                    
                    let protect_result = unsafe {
                        VirtualProtectEx(
                            process_handle,
                            (address + total_read) as _,
                            current_chunk,
                            protection,
                            &mut old_protect,
                        )
                    };

                    if protect_result.is_ok() {
                        let read_result = unsafe {
                            ReadProcessMemory(
                                process_handle,
                                (address + total_read) as _,
                                buffer.as_mut_ptr().add(total_read) as _,
                                current_chunk,
                                Some(&mut bytes_read),
                            )
                        };

                        
                        unsafe {
                            let _ = VirtualProtectEx(
                                process_handle,
                                (address + total_read) as _,
                                current_chunk,
                                old_protect,
                                &mut old_protect,
                            );
                        }

                        if read_result.is_ok() && bytes_read > 0 {
                            total_read += bytes_read;
                            if total_read >= mem::size_of::<ImageDosHeader>() {
                                break;
                            }
                            
                            break;
                        }
                    }
                    
                    thread::sleep(Duration::from_millis(10));
                }

                if total_read >= mem::size_of::<ImageDosHeader>() {
                    break;
                }
            }
            
            retry_count += 1;
            if retry_count < 10 {
                
                thread::sleep(Duration::from_millis(50 * (1 << retry_count.min(4))));
            }
        }

        if total_read < mem::size_of::<ImageDosHeader>() {
            return Err(anyhow::anyhow!("Failed to read complete DOS header after {} retries", retry_count));
        }

        let header = unsafe {
            std::ptr::read_unaligned(buffer.as_ptr() as *const ImageDosHeader)
        };

        
        if header.e_magic != 0x5A4D {
            return Err(anyhow::anyhow!("Invalid DOS signature: {:x}", header.e_magic));
        }

        if header.e_lfanew <= 0 || header.e_lfanew > 0x1000 {
            return Err(anyhow::anyhow!("Invalid e_lfanew value: {}", header.e_lfanew));
        }

        Ok(header)
    }

    fn read_nt_headers(process_handle: HANDLE, address: usize) -> Result<ImageNtHeaders64> {
        let mut buffer = vec![0u8; mem::size_of::<ImageNtHeaders64>()];
        let mut total_read = 0;
        let mut retry_count = 0;

        
        let chunk_sizes = [
            mem::size_of::<ImageNtHeaders64>(),
            0x80,
            0x40,
            0x20,
            0x10,
            0x8,
            0x4,
        ];

        while total_read < mem::size_of::<ImageNtHeaders64>() && retry_count < 10 {
            for &chunk_size in &chunk_sizes {
                let remaining = mem::size_of::<ImageNtHeaders64>() - total_read;
                let current_chunk = remaining.min(chunk_size);
                let mut bytes_read = 0;

                
                for &protection in &[
                    PAGE_EXECUTE_READ,
                    PAGE_READONLY,
                    PAGE_READWRITE,
                    PAGE_EXECUTE_READWRITE,
                ] {
                    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                    
                    
                    let protect_result = unsafe {
                        VirtualProtectEx(
                            process_handle,
                            (address + total_read) as _,
                            current_chunk,
                            protection,
                            &mut old_protect,
                        )
                    };

                    if protect_result.is_ok() {
                        let read_result = unsafe {
                            ReadProcessMemory(
                                process_handle,
                                (address + total_read) as _,
                                buffer.as_mut_ptr().add(total_read) as _,
                                current_chunk,
                                Some(&mut bytes_read),
                            )
                        };

                        
                        unsafe {
                            let _ = VirtualProtectEx(
                                process_handle,
                                (address + total_read) as _,
                                current_chunk,
                                old_protect,
                                &mut old_protect,
                            );
                        }

                        if read_result.is_ok() && bytes_read > 0 {
                            total_read += bytes_read;
                            if total_read >= mem::size_of::<ImageNtHeaders64>() {
                                break;
                            }
                            
                            break;
                        }
                    }
                    
                    thread::sleep(Duration::from_millis(10));
                }

                if total_read >= mem::size_of::<ImageNtHeaders64>() {
                    break;
                }
            }
            
            retry_count += 1;
            if retry_count < 10 {
                
                thread::sleep(Duration::from_millis(50 * (1 << retry_count.min(4))));
            }
        }

        if total_read < mem::size_of::<ImageNtHeaders64>() {
            return Err(anyhow::anyhow!("Failed to read complete NT headers after {} retries", retry_count));
        }

        let headers = unsafe {
            std::ptr::read_unaligned(buffer.as_ptr() as *const ImageNtHeaders64)
        };

        
        if headers.signature != 0x4550 {
            return Err(anyhow::anyhow!("Invalid NT signature: {:x}", headers.signature));
        }

        
        if headers.file_header.machine != 0x8664 { 
            return Err(anyhow::anyhow!("Invalid machine type: {:x}", headers.file_header.machine));
        }

        if headers.optional_header.magic != 0x20B { 
            return Err(anyhow::anyhow!("Invalid optional header magic: {:x}", headers.optional_header.magic));
        }

        Ok(headers)
    }

    fn read_sections(
        process_handle: HANDLE,
        base_address: usize,
        nt_headers: &ImageNtHeaders64,
    ) -> Result<Vec<Section>> {
        let mut sections = Vec::new();
        
        
        if let Ok(header_sections) = Self::read_sections_from_headers(process_handle, base_address, nt_headers) {
            if !header_sections.is_empty() {
                return Ok(header_sections);
            }
        }

        
        info!("Attempting memory scan for sections...");
        let image_size = nt_headers.optional_header.size_of_image as usize;
        let mut current_addr = base_address;
        let end_addr = base_address + image_size;
        let mut section_count = 0;

        while current_addr < end_addr && section_count < 96 {
            let mut mbi = unsafe { mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
            
            if unsafe {
                VirtualQueryEx(
                    process_handle,
                    Some(current_addr as *const _),
                    &mut mbi,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            } == 0 {
                break;
            }

            if mbi.State == MEM_COMMIT {
                let protection = mbi.Protect.0;
                let is_executable = protection & PAGE_EXECUTE_READ.0 != 0 
                    || protection & PAGE_EXECUTE_READWRITE.0 != 0;
                let is_readable = protection & PAGE_READONLY.0 != 0 
                    || protection & PAGE_READWRITE.0 != 0;
                
                if is_executable || is_readable {
                    let section_size = mbi.RegionSize;
                    if section_size > 0 && section_size <= MAX_SECTION_SIZE {
                        let characteristics = if is_executable {
                            0xE0000020 
                        } else {
                            0x40000000 
                        };

                        sections.push(Section {
                            address: current_addr,
                            size: section_size,
                            characteristics,
                            name: format!("Section_{:X}", section_count),
                        });
                        section_count += 1;
                    }
                }
            }
            
            current_addr = (current_addr as usize + mbi.RegionSize) as usize;
        }

        if sections.is_empty() {
            warn!("No sections found through memory scan, using fallback section");
            sections.push(Section {
                address: base_address,
                size: image_size,
                characteristics: 0xE0000020,
                name: "MainImage".to_string(),
            });
        } else {
            info!("Found {} sections through memory scan", sections.len());
        }

        Ok(sections)
    }

    fn read_sections_from_headers(
        process_handle: HANDLE,
        base_address: usize,
        nt_headers: &ImageNtHeaders64,
    ) -> Result<Vec<Section>> {
        let mut sections = Vec::new();
        let mut _consecutive_invalid = 0;
        
        let first_section = base_address + mem::size_of::<ImageDosHeader>() as usize
            + nt_headers.file_header.size_of_optional_header as usize
            + mem::size_of::<u32>() as usize 
            + mem::size_of::<ImageFileHeader>() as usize;

        
        for &protection in &[
            PAGE_EXECUTE_READ,
            PAGE_READONLY,
            PAGE_READWRITE,
            PAGE_EXECUTE_READWRITE,
        ] {
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            let total_size = nt_headers.file_header.number_of_sections as usize * mem::size_of::<ImageSectionHeader>();
            
            if unsafe {
                VirtualProtectEx(
                    process_handle,
                    first_section as _,
                    total_size,
                    protection,
                    &mut old_protect,
                )
            }.is_ok() {
                let mut section_headers_buffer = vec![0u8; total_size];
                let mut bytes_read = 0;

                let read_result = unsafe {
                    ReadProcessMemory(
                        process_handle,
                        first_section as _,
                        section_headers_buffer.as_mut_ptr() as _,
                        total_size,
                        Some(&mut bytes_read),
                    )
                };

                
                unsafe {
                    let _ = VirtualProtectEx(
                        process_handle,
                        first_section as _,
                        total_size,
                        old_protect,
                        &mut old_protect,
                    );
                };

                if read_result.is_ok() && bytes_read == total_size {
                    
                    for i in 0..nt_headers.file_header.number_of_sections as usize {
                        let offset = i * mem::size_of::<ImageSectionHeader>();
                        let section_header: ImageSectionHeader = unsafe {
                            std::ptr::read_unaligned(section_headers_buffer[offset..].as_ptr() as *const _)
                        };

                        let section_address = base_address + section_header.virtual_address as usize;
                        
                        
                        if section_header.misc == 0 || section_header.misc as usize > MAX_SECTION_SIZE {
                            _consecutive_invalid += 1;
                            continue;
                        }

                        if section_address < base_address || 
                           section_address >= base_address + nt_headers.optional_header.size_of_image as usize {
                            _consecutive_invalid += 1;
                            continue;
                        }

                        
                        let name = String::from_utf8_lossy(&section_header.name)
                            .trim_matches(|c: char| !VALID_SECTION_CHARS.contains(&(c as u8)))
                            .to_string();

                        sections.push(Section {
                            address: section_address,
                            size: section_header.misc as usize,
                            characteristics: section_header.characteristics,
                            name: if name.is_empty() { format!("Section{}", i) } else { name },
                        });
                        _consecutive_invalid = 0;
                    }

                    if !sections.is_empty() {
                        break;
                    }
                }
            }
        }

        Ok(sections)
    }

    fn read_string_with_size(&self, address: usize, max_size: usize) -> Result<String> {
        let mut buffer = vec![0u8; max_size];
        let mut bytes_read = 0;

        unsafe {
            ReadProcessMemory(
                self.process_handle,
                address as _,
                buffer.as_mut_ptr() as _,
                max_size,
                Some(&mut bytes_read),
            )
            .context("Failed to read string")?;
        }

        if bytes_read == 0 {
            return Ok(String::new());
        }

        buffer.truncate(bytes_read);
        
        
        let null_pos = buffer.iter().position(|&b| b == 0).unwrap_or(bytes_read);
        buffer.truncate(null_pos);

        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }

    pub fn process_relocations(&self) -> Result<()> {
        
        
        Ok(())
    }

    pub fn fix_imports(&self) -> Result<()> {
        let import_dir = &self.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if import_dir.virtual_address == 0 {
            return Ok(());
        }

        let mut current_desc_addr = self.base_address + import_dir.virtual_address as usize;
        let mut processed_dlls = Vec::new();

        loop {
            let mut desc = ImageImportDescriptor {
                original_first_thunk: 0,
                time_date_stamp: 0,
                forwarder_chain: 0,
                name: 0,
                first_thunk: 0,
            };

            
            for retry in 0..3 {
                let mut bytes_read = 0;
                if unsafe {
                    ReadProcessMemory(
                        self.process_handle,
                        current_desc_addr as _,
                        &mut desc as *mut _ as _,
                        mem::size_of::<ImageImportDescriptor>(),
                        Some(&mut bytes_read),
                    )
                }.is_ok() && bytes_read == mem::size_of::<ImageImportDescriptor>() {
                    break;
                }
                thread::sleep(Duration::from_millis(50 * (1 << retry)));
            }

            if desc.first_thunk == 0 && desc.original_first_thunk == 0 {
                break;
            }

            
            if let Ok(dll_name) = self.read_string_with_size(self.base_address + desc.name as usize, 256) {
                if !dll_name.is_empty() && !processed_dlls.contains(&dll_name) {
                    processed_dlls.push(dll_name.clone());
                    info!("Processing imports from: {}", dll_name);

                    
                    let mut thunk_addr = if desc.original_first_thunk != 0 {
                        self.base_address + desc.original_first_thunk as usize
                    } else {
                        self.base_address + desc.first_thunk as usize
                    };

                    loop {
                        let mut thunk_data: u64 = 0;
                        if unsafe {
                            ReadProcessMemory(
                                self.process_handle,
                                thunk_addr as _,
                                &mut thunk_data as *mut _ as _,
                                mem::size_of::<u64>(),
                                None,
                            )
                        }.is_err() || thunk_data == 0 {
                            break;
                        }

                        
                        if thunk_data & (1u64 << 63) != 0 {
                            let ordinal = thunk_data & 0xFFFF;
                            debug!("Import by ordinal: {}", ordinal);
                        } else {
                            
                            let name_addr = self.base_address + (thunk_data & 0x7FFFFFFFFFFFFFFF) as usize;
                            if let Ok(func_name) = self.read_string_with_size(name_addr + 2, 256) {
                                debug!("Import by name: {}", func_name);
                            }
                        }

                        thunk_addr += mem::size_of::<u64>();
                    }
                }
            }

            current_desc_addr += mem::size_of::<ImageImportDescriptor>();
        }

        Ok(())
    }
} 