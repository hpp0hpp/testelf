from elftools.elf.elffile import ELFFile
from keystone import *

# 解析 ELF 文件中的符号表
def parse_symbols(elf_file_path):
    symbols = {}
    with open(elf_file_path, 'rb') as f:
        elffile = ELFFile(f)
        symtab = elffile.get_section_by_name('.dynsym')
        if not symtab:
            raise ValueError("ELF 文件中没有符号表 (.symtab)")
        for symbol in symtab.iter_symbols():
            symbols[symbol.name] = symbol.entry['st_value']
    return symbols

# 替换指令中的符号为实际地址
def resolve_symbols(instructions, symbols):
    resolved_instructions = []
    for address, instruction in instructions:
        for symbol, addr in symbols.items():
            if symbol in instruction:
                instruction = instruction.replace(symbol, f"0x{addr:x}")
        resolved_instructions.append((address, instruction))
    return resolved_instructions

# 示例汇编指令
instructions = [
    ("4000", "bl __memset_chk"),  # ARM64 的分支指令
    ("4004", "b 0x4010"),         # ARM64 的无条件跳转
    ("4008", "ldr x0, [x1]")      # ARM64 的加载指令
]

# 解析 ELF 文件中的符号
elf_file_path = r"D:\crack\jiongciyuan\libcore.so"  # 替换为你的 ELF 文件路径
symbols = parse_symbols(elf_file_path)

# 替换符号为地址
resolved_instructions = resolve_symbols(instructions, symbols)

# 使用 Keystone 汇编（ARM64 模式）
ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
for address, instruction in resolved_instructions:
    addr = int(address, 16)
    try:
        encoding, count = ks.asm(instruction, addr)
        print(f"Address: {address}, Instruction: {instruction}")
        print(f"Machine Code: {' '.join(format(byte, '02x') for byte in encoding)}\n")
    except KsError as e:
        print(f"ERROR: Failed to assemble instruction '{instruction}' at address {address}: {e}")