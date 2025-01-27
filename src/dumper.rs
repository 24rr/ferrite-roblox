use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, info, warn};
use std::ffi::OsString;
use std::fs::File;
use std::io::Write;
use std::os::windows::ffi::OsStringExt;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualProtectEx, VirtualQueryEx, PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS,
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE,
    MEM_COMMIT, MEM_MAPPED, MEM_PRIVATE, PAGE_GUARD, PAGE_NOACCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_VM_OPERATION, PROCESS_QUERY_INFORMATION,
};

use crate::pe::{PEImage, Section};

pub struct Dumper {
    process_handle: HANDLE,
    _threshold: f32,
    output_dir: String,
}

impl Dumper {
    pub fn new(process_name: &str, threshold: f32, _resolve_imports: bool, output_dir: Option<String>) -> Result<Self> {
        let process_handle = unsafe {
            OpenProcess(
                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                false,
                Self::find_process_id(process_name)?,
            )
        }
        .with_context(|| format!("Failed to open process: {}", process_name))?;

        Ok(Self {
            process_handle,
            _threshold: threshold,
            output_dir: output_dir.unwrap_or_else(|| ".".to_string()),
        })
    }

    pub fn dump(&self) -> Result<()> {
        let pe = PEImage::from_process(self.process_handle)?;
        info!("Found PE image at base: {:x}", pe.base_address());

        let sections = pe.sections()?;
        let pb = ProgressBar::new(sections.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} sections")
            .unwrap()
            .progress_chars("█░░"));

        for section in &sections {
            pb.inc(1);
            self.decrypt_section_with_protection(section, PAGE_EXECUTE_READWRITE)?;
        }
        pb.finish_and_clear();

        info!("Processing relocations...");
        pe.process_relocations()?;

        info!("Resolving imports...");
        pe.resolve_imports()?;
        pe.fix_imports()?;

        info!("Dumping PE image to file...");
        let buffer = pe.to_bytes()?;
        let output_path = format!("{}/dumped.exe", self.output_dir);
        let mut file = File::create(&output_path)?;
        file.write_all(&buffer)?;

        info!("Successfully wrote {} bytes to {}", buffer.len(), output_path);
        Ok(())
    }

    fn decrypt_section_with_protection(&self, section: &Section, protection: PAGE_PROTECTION_FLAGS) -> Result<()> {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let mut total_processed = 0;
        let mut current_addr = section.address;

        while total_processed < section.size {
            
            let query_size = unsafe {
                VirtualQueryEx(
                    self.process_handle,
                    Some(current_addr as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            
            if query_size == 0 {
                warn!("Failed to query memory at {:x}, skipping", current_addr);
                break;
            }

            
            if mbi.State != MEM_COMMIT ||
               (mbi.Type != MEM_PRIVATE && mbi.Type != MEM_MAPPED) ||
               (mbi.Protect & PAGE_GUARD == PAGE_GUARD) ||
               (mbi.Protect & PAGE_NOACCESS == PAGE_NOACCESS) {
                current_addr += mbi.RegionSize;
                total_processed += mbi.RegionSize;
                continue;
            }

            
            let remaining = section.size - total_processed;
            let chunk_size = remaining.min(mbi.RegionSize as usize);
            
            
            let protection_attempts = [
                protection,
                PAGE_EXECUTE_READWRITE,
                PAGE_READWRITE,
                PAGE_EXECUTE_READ,
                PAGE_READONLY,
                PAGE_PROTECTION_FLAGS(0x40), 
                PAGE_PROTECTION_FLAGS(0x80), 
            ];

            let mut processed = false;
            for &attempt_protection in &protection_attempts {
                let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                
                
                match unsafe {
                    VirtualProtectEx(
                        self.process_handle,
                        current_addr as _,
                        chunk_size,
                        attempt_protection,
                        &mut old_protect,
                    )
                } {
                    Ok(_) => {
                        
                        if let Ok(()) = self.process_memory_chunk(current_addr, chunk_size) {
                            processed = true;
                            
                            
                            unsafe {
                                let _ = VirtualProtectEx(
                                    self.process_handle,
                                    current_addr as _,
                                    chunk_size,
                                    old_protect,
                                    &mut old_protect,
                                );
                            }
                            break;
                        }

                        
                        unsafe {
                            let _ = VirtualProtectEx(
                                self.process_handle,
                                current_addr as _,
                                chunk_size,
                                old_protect,
                                &mut old_protect,
                            );
                        }
                    }
                    Err(_) => continue,
                }
            }

            if !processed {
                debug!("Failed to process memory at {:x} with any protection", current_addr);
            }

            current_addr += chunk_size;
            total_processed += chunk_size;
        }

        Ok(())
    }

    fn process_memory_chunk(&self, address: usize, size: usize) -> Result<()> {
        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0;

        
        if unsafe {
            ReadProcessMemory(
                self.process_handle,
                address as _,
                buffer.as_mut_ptr() as _,
                size,
                Some(&mut bytes_read),
            )
        }.is_ok() && bytes_read > 0 {
            
            if unsafe {
                WriteProcessMemory(
                    self.process_handle,
                    address as _,
                    buffer.as_ptr() as _,
                    bytes_read,
                    None,
                )
            }.is_ok() {
                return Ok(());
            }
        }

        Err(anyhow::anyhow!("Failed to process memory chunk"))
    }

    fn find_process_id(process_name: &str) -> Result<u32> {
        let h_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
            .context("Failed to create process snapshot")?;

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let mut found_pid = None;

        unsafe {
            if Process32FirstW(h_snapshot, &mut entry).is_ok() {
                loop {
                    let current_name = OsString::from_wide(&entry.szExeFile[..])
                        .to_string_lossy()
                        .into_owned();
                    
                    if current_name.trim_end_matches('\0') == process_name {
                        found_pid = Some(entry.th32ProcessID);
                        break;
                    }

                    if !Process32NextW(h_snapshot, &mut entry).is_ok() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(h_snapshot);
        }

        found_pid.context(format!("Process '{}' not found", process_name))
    }
}

impl Drop for Dumper {
    fn drop(&mut self) {
        if !self.process_handle.is_invalid() {
            unsafe { let _ = CloseHandle(self.process_handle); }
        }
    }
} 