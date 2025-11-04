#!/usr/bin/env python3
"""
patch_jmps.py

读取 ARM64 so 文件，根据 jmps.json 的记录将间接跳转替换为直接跳转（尽可能）。

用法示例:
    python patch_jmps.py --elf path/to/libfoo.so --jmps jmps.json

注意:
 - 本脚本尝试使用单条指令（4 字节）替换原位置（ARM64 指令宽度固定为 4 字节）。
 - 当 Keystone 无法编码为 4 字节（例如立即数超出范围）时，会记录为警告并跳过；更复杂的 trampoline/veneer 需要额外实现。
 - 如果 target 为字符串，会从 ELF 的符号表 (.dynsym/.symtab) 中解析符号地址。
"""

import argparse
import json
import os
import io
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, KsError

NOP4 = bytes([0x1f, 0x20, 0x03, 0xd5])  # ARM64 nop (little-endian)
def get_symbol_offset(elffile:ELFFile, sym_name):
    dynsym = elffile.get_section_by_name('.dynsym')


    sym_idx = 0
    for  s in dynsym.iter_symbols():

        if s.name == sym_name :
            break
        sym_idx += 1

    bss_seg = elffile.get_section_by_name('.bss')
    # 获取结束地址
    bss_end_addr = bss_seg['sh_addr'] + bss_seg['sh_size']
    return bss_end_addr + (sym_idx-1)*8 # -1 是因为第一个符号是空符号


def load_jmps(jmps_path):
    with open(jmps_path, 'r', encoding='utf-8') as f:
        return json.load(f)



def assemble_arm64(ks: Ks, asm: str, addr: int):
    try:
        encoding, count = ks.asm(asm, addr)
        return bytes(encoding)
    except KsError as e:
        return None


def map_cond(cond: str):
    # 简单映射; 'cc' 在 ARM 术语中等同于 'lo'
    if cond == 'cc':
        return 'lo'
    return cond

def vaddr_to_offset(elffile, vaddr):
    text_segment = elffile.get_section_by_name('.text')
    return vaddr - text_segment['sh_addr'] + text_segment['sh_offset']
    


def patch_file(elf_path, jmps_path, out_path=None):
    if out_path is None:
        base, ext = os.path.splitext(elf_path)
        out_path = base + '_patched' + ext

    # 先把 ELF 文件读到内存中，避免 elftools 在后续访问时因文件已关闭而报错
    with open(elf_path, 'rb') as f:
        file_bytes = f.read()
    elffile = ELFFile(io.BytesIO(file_bytes))
    data = bytearray(file_bytes)

    jmps = load_jmps(jmps_path)
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

    patched = []
    warnings = []

    for addr_str, info in jmps.items():
        try:
            addr = int(addr_str)
        except Exception:
            warnings.append(f"invalid jmps key: {addr_str}")
            continue

        # choose first target by default (如果是条件分支, 我们选择第二个为分支目标)
        targets = info.get('targets', [])
        if not targets:
            warnings.append(f"no targets for {hex(addr)}")
            continue

        inst_type = info.get('type', '').lower()

        # For conditional 'br', usually targets[0] is fall-through, targets[1] is branch target
        chosen_target = None
        if inst_type == 'br' and len(targets) >= 2:
            chosen_target = targets[1]
        else:
            chosen_target = targets[0]

        # resolve symbol if needed
        if isinstance(chosen_target, str):
   
            target_addr = get_symbol_offset(elffile, chosen_target)
        else:
            target_addr = int(chosen_target)

        # build asm for direct branches
        if inst_type == 'blr':
            asm = f"bl 0x{target_addr:x}"
        elif inst_type == 'br':
            cond = info.get('csx_cond')
            if cond:
                cond_mapped = map_cond(cond)
                asm = f"b.{cond_mapped} 0x{target_addr:x}"
            else:
                asm = f"b 0x{target_addr:x}"
        else:
            # 默认使用 bl
            asm = f"bl 0x{target_addr:x}"

        file_offset = vaddr_to_offset(elffile, addr)
        if file_offset is None:
            warnings.append(f"address {hex(addr)} not in any PT_LOAD segment")
            continue

        encoding = assemble_arm64(ks, asm, addr)
        if not encoding:
            warnings.append(f"assemble failed for {hex(addr)} -> '{asm}'")
            continue

        if len(encoding) > 4:
            warnings.append(f"assembled size >4 for {hex(addr)} -> {len(encoding)} bytes; asm='{asm}' (skipped)")
            continue

        # pad if needed
        if len(encoding) < 4:
            encoding = encoding + (NOP4 * ((4 - len(encoding)) // 4))

        # apply patch
        data[file_offset:file_offset+4] = encoding[:4]
        patched.append((addr, asm, file_offset, encoding))

    # write out
    with open(out_path, 'wb') as fo:
        fo.write(data)

    # report
    print(f"Patched file written to: {out_path}")
    print(f"Patched count: {len(patched)}")
    for addr, asm, off, enc in patched:
        print(f"PATCH {hex(addr)} @fileoff {hex(off)} : {asm} -> {enc.hex()}")

    if warnings:
        print('\nWarnings:')
        for w in warnings:
            print(' -', w)


def main():
    # ap = argparse.ArgumentParser(description='Patch ARM64 so according to jmps.json')
    # ap.add_argument('--elf', '-e', required=True, help='path to ELF/so file')
    # ap.add_argument('--jmps', '-j', required=True, help='path to jmps.json')
    # ap.add_argument('--out', '-o', required=False, help='output patched file path')
    # args = ap.parse_args()

    # patch_file(args.elf, args.jmps, args.out)
    patch_file(r"D:\crack\jiongciyuan\libcore.so" , r'C:\Users\admin\AppData\Roaming\Binary Ninja\plugins\dejmp\jmps.json', None)

if __name__ == '__main__':
    main()
