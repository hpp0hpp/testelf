#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARM64反混淆工具
功能：分析ARM64 SO文件，追踪间接跳转，通过模拟执行获取跳转目标，并patch为直接跳转
"""

import os
import sys
import struct
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum

# 导入寄存器追踪器的工具函数
from register_tracer import RegisterTracer as TextRegisterTracer

try:
    from capstone import *
    from capstone.arm64 import *
except ImportError:
    print("错误: 请安装 capstone: pip install capstone")
    sys.exit(1)

try:
    from keystone import *
except ImportError:
    print("错误: 请安装 keystone: pip install keystone-engine")
    sys.exit(1)

try:
    from unicorn import *
    from unicorn.arm64_const import *
except ImportError:
    print("错误: 请安装 unicorn: pip install unicorn")
    sys.exit(1)

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError:
    print("错误: 请安装 pyelftools: pip install pyelftools")
    sys.exit(1)


class JumpType(Enum):
    """跳转类型"""
    DIRECT = 1      # 直接跳转 (B, BL)
    INDIRECT = 2    # 间接跳转 (BR, BLR)
    CONDITIONAL = 3 # 条件跳转 (B.EQ, B.NE等)
    RET = 4         # 返回


@dataclass
class JumpRecord:
    """跳转记录"""
    address: int                    # 跳转指令地址
    jump_type: JumpType            # 跳转类型
    target_address: Optional[int]  # 跳转目标地址
    register: Optional[str]        # 使用的寄存器（间接跳转）
    related_instructions: List[int] = field(default_factory=list)  # 相关指令地址
    condition: Optional[str] = None # 条件码（CSEL指令的条件，如'eq', 'ne', 'gt'等）
    condition_true: Optional[int] = None   # 条件为真时的目标
    condition_false: Optional[int] = None  # 条件为假时的目标


@dataclass
class FunctionInfo:
    """函数信息"""
    start_address: int
    end_address: Optional[int]
    name: str
    jump_records: List[JumpRecord] = field(default_factory=list)
    called_functions: Set[int] = field(default_factory=set)


class ARM64Analyzer:
    """ARM64分析器"""
    
    def __init__(self, so_path: str, enable_mem_trace: bool = False):
        self.so_path = so_path
        self.so_data = None
        self.base_address = 0
        self.load_address = 0x000000  # 模拟器加载基址
        
        # data.bin数据
        self.lib_data = {}  # 存储data.bin内容
        
        # ELF段信息
        self.segments = []  # 保存所有段信息
        
        # 调试选项
        self.enable_mem_trace = enable_mem_trace  # 是否启用内存访问追踪
        
        # Capstone反汇编器
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.cs.detail = True
        
        # Keystone汇编器
        self.ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        
        # 分析结果
        self.functions: Dict[int, FunctionInfo] = {}
        self.patches: Dict[int, bytes] = {}  # 地址 -> 新的指令字节
        
        # 加载SO文件
        self._load_so()
        
        # 加载额外的库
        self._load_extra_libs()
    
    def _load_so(self):
        """加载SO文件并解析段信息"""
        with open(self.so_path, 'rb') as f:
            self.so_data = bytearray(f.read())
        
        # 解析ELF获取段信息
        with open(self.so_path, 'rb') as f:
            elf = ELFFile(f)
            
            # 获取所有可加载的段
            for segment in elf.iter_segments():
                if segment['p_type'] == 'PT_LOAD':
                    seg_info = {
                        'vaddr': segment['p_vaddr'],
                        'offset': segment['p_offset'],
                        'size': segment['p_filesz'],
                        'mem_size': segment['p_memsz'],
                        'flags': segment['p_flags'],
                        'is_exec': bool(segment['p_flags'] & 0x1),  # 可执行
                        'is_write': bool(segment['p_flags'] & 0x2), # 可写
                        'is_read': bool(segment['p_flags'] & 0x4),  # 可读
                        'data': segment.data()
                    }
                    self.segments.append(seg_info)
                    
                    # 第一个可执行段作为基址
                    if self.base_address == 0 and seg_info['is_exec']:
                        self.base_address = seg_info['vaddr']
        
        print(f"[*] 加载SO: {self.so_path}")
        print(f"[*] 文件大小: {len(self.so_data)} 字节")
        print(f"[*] 基址: 0x{self.base_address:x}")
        print(f"[*] 加载段数: {len(self.segments)}")
        
        for i, seg in enumerate(self.segments):
            flags = ''
            if seg['is_read']: flags += 'R'
            if seg['is_write']: flags += 'W'
            if seg['is_exec']: flags += 'X'
            print(f"    段{i}: 0x{seg['vaddr']:08x} - 0x{seg['vaddr']+seg['mem_size']:08x} "
                  f"[{flags}] size=0x{seg['size']:x}")
    
    def _load_extra_libs(self):
        """加载data.bin文件（如果存在）"""
        # 查找data.bin文件
        data_bin_path = 'data.bin'
        if os.path.exists(data_bin_path):
            try:
                with open(data_bin_path, 'rb') as f:
                    data = f.read()
                self.lib_data['data.bin'] = data
                print(f"[*] 加载data.bin: {len(data)} 字节")
            except Exception as e:
                print(f"[-] 加载data.bin失败: {e}")
        else:
            print(f"[*] 未找到data.bin文件")
    
    def offset_to_address(self, offset: int) -> int:
        """文件偏移转虚拟地址"""
        return self.base_address + offset
    
    def address_to_offset(self, address: int) -> int:
        """虚拟地址转文件偏移"""
        return address - self.base_address
    
    def is_address_in_current_so(self, address: int) -> bool:
        """
        检查地址是否在当前SO的范围内
        
        Args:
            address: 要检查的虚拟地址
            
        Returns:
            True: 地址在当前SO内
            False: 地址在外部（其他库或无效地址）
        """
        # 检查地址是否在任何一个段的范围内
        for seg in self.segments:
            seg_start = seg['vaddr']
            seg_end = seg['vaddr'] + seg['mem_size']
            
            if seg_start <= address < seg_end:
                return True
        
        return False
    
    def read_code(self, offset: int, size: int) -> bytes:
        """读取代码"""
        if offset < 0 or offset + size > len(self.so_data):
            raise ValueError(f"无效的偏移: 0x{offset:x}")
        return bytes(self.so_data[offset:offset + size])
    
    def disassemble_function(self, start_offset: int, end_offset: Optional[int] = None) -> List[Tuple[int, CsInsn]]:
        """
        反汇编函数
        
        Args:
            start_offset: 起始偏移
            end_offset: 结束偏移（可选）
            
        Returns:
            [(地址, 指令)] 列表
        """
        instructions = []
        current_offset = start_offset
        start_addr = self.offset_to_address(start_offset)
        
        print(f"\n[*] 反汇编函数: 0x{start_addr:x}")
        
        max_size = 0x10000  # 最大搜索范围
        if end_offset:
            max_size = min(max_size, end_offset - start_offset)
        
        code = self.read_code(start_offset, max_size)
        
        for insn in self.cs.disasm(code, start_addr):
            instructions.append((insn.address, insn))
            
            # 检查是否到达结束条件
            if end_offset and insn.address >= self.offset_to_address(end_offset):
                break
            
            # 检查是否为RET指令
            if insn.mnemonic == 'ret':
                print(f"[*] 找到RET指令: 0x{insn.address:x}")
                break
        
        print(f"[*] 反汇编完成，共 {len(instructions)} 条指令")
        return instructions
    
    def is_indirect_jump(self, insn: CsInsn) -> bool:
        """判断是否为间接跳转"""
        return insn.mnemonic in ['br', 'blr']
    
    def is_conditional_instruction(self, insn: CsInsn) -> bool:
        """判断是否为条件指令"""
        # 条件分支
        if insn.mnemonic.startswith('b.'):
            return True
        # 条件选择 CSEL, CSINC等
        if insn.mnemonic.startswith('cs'):
            return True
        return False
    
    def get_jump_register(self, insn: CsInsn) -> Optional[str]:
        """获取跳转使用的寄存器"""
        if not self.is_indirect_jump(insn):
            return None
        
        if len(insn.operands) > 0:
            op = insn.operands[0]
            if op.type == ARM64_OP_REG:
                return insn.reg_name(op.reg)
        
        return None
    
    def trace_register_dependencies(self, instructions: List[Tuple[int, CsInsn]], 
                                    target_insn_idx: int, 
                                    target_reg: str,
                                    debug: bool = False) -> List[int]:
        """
        追踪寄存器依赖 - 使用 RegisterTracer 的算法
        
        Args:
            instructions: 指令列表
            target_insn_idx: 目标指令索引
            target_reg: 目标寄存器
            debug: 是否输出调试信息
            
        Returns:
            相关指令的地址列表
        """
        related_addresses = []
        visited_pairs = set()  # (寄存器, 索引) 对
        
        # 复用 RegisterTracer 的 normalize_register 方法
        normalize_reg = TextRegisterTracer.normalize_register
        
        def trace_reg(reg: str, start_idx: int, depth: int = 0):
            """
            递归追踪寄存器 - 改进版：使用类似 RegisterTracer 的逻辑
            支持 MOVK 序列追踪
            """
            reg = normalize_reg(reg)
            
            # 使用 (寄存器, 索引) 对避免重复追踪
            trace_key = (reg, start_idx)
            if trace_key in visited_pairs:
                if debug:
                    print(f"{'  '*depth}[跳过] {reg} @ idx={start_idx} (已访问)")
                return
            visited_pairs.add(trace_key)
            
            if debug:
                print(f"{'  '*depth}[追踪] {reg} @ idx={start_idx}")
            
            # 向上查找定义该寄存器的指令
            for i in range(start_idx - 1, -1, -1):
                addr, insn = instructions[i]
                
                # 检查是否写入目标寄存器
                writes_target = False
                source_regs = []
                
                # 分析操作数
                opcode = insn.mnemonic.lower()
                
                # 检查目标寄存器
                dest_reg = None
                
                # 存储指令不修改寄存器
                if opcode not in ['str', 'stur', 'stp', 'strb', 'strh', 'cmp', 'cmn', 'tst']:
                    if len(insn.operands) > 0:
                        first_op = insn.operands[0]
                        if first_op.type == ARM64_OP_REG:
                            dest_reg = normalize_reg(insn.reg_name(first_op.reg))
                
                # 检查是否写入目标寄存器
                if dest_reg == reg:
                    writes_target = True
                    
                    # 提取所有源寄存器（更完善的逻辑）
                    for j, op in enumerate(insn.operands):
                        if j == 0 and dest_reg:
                            continue  # 跳过目标寄存器
                        
                        if op.type == ARM64_OP_REG:
                            source_regs.append(insn.reg_name(op.reg))
                        elif op.type == ARM64_OP_MEM:
                            # 内存操作数，提取基址和索引寄存器
                            if op.mem.base != 0:
                                source_regs.append(insn.reg_name(op.mem.base))
                            if op.mem.index != 0:
                                source_regs.append(insn.reg_name(op.mem.index))
                
                if writes_target:
                    # 记录这条指令
                    related_addresses.append(addr)
                    
                    if debug:
                        print(f"{'  '*depth}  [找到] 0x{addr:x}: {insn.mnemonic} {insn.op_str}")
                        print(f"{'  '*depth}    源寄存器: {source_regs}")
                    
                    # 递归追踪源寄存器
                    for src_reg in source_regs:
                        trace_reg(src_reg, i, depth + 1)
                    
                    # 判断是否为初始赋值指令（参考 RegisterTracer.is_initial_value_instruction）
                    is_initial = False
                    if insn.mnemonic in ['mov', 'movz', 'movn']:
                        if len(insn.operands) >= 2:
                            second_op = insn.operands[1]
                            if second_op.type == ARM64_OP_IMM:
                                is_initial = True
                    elif insn.mnemonic in ['adrp', 'adr']:
                        is_initial = True
                    
                    if is_initial:
                        if debug:
                            print(f"{'  '*depth}  [停止] 找到初始赋值")
                        break  # 找到初始赋值，停止追踪
                    
                    # 如果是MOVK，需要继续向上找该寄存器的前续赋值（MOV）
                    # 参考 RegisterTracer.trace_register 的逻辑
                    if insn.mnemonic == 'movk':
                        if debug:
                            print(f"{'  '*depth}  [继续] MOVK指令，继续向上查找MOV")
                        continue  # 不break，继续向上查找
                    
                    # 其他情况停止向上搜索
                    if debug:
                        print(f"{'  '*depth}  [停止] 非MOVK指令")
                    break
        
        # 开始追踪
        trace_reg(target_reg, target_insn_idx)
        
        # 按地址排序
        related_addresses.sort()
        
        return related_addresses
    
    def create_emulator(self, instructions: List[Tuple[int, CsInsn]], 
                       related_addresses: List[int],
                       enable_hooks: bool = False) -> Uc:
        """
        创建模拟器并映射内存
        
        Args:
            instructions: 所有指令
            related_addresses: 需要执行的指令地址
            enable_hooks: 是否启用hook
            
        Returns:
            配置好的Unicorn模拟器
        """
        # 创建ARM64模拟器
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        
        print(f"[*] 创建模拟器...")
        
        # 映射栈段
        STACK_ADDRESS = 0x40000000
        STACK_SIZE = 2 * 1024 * 1024  # 2MB栈
        mu.mem_map(STACK_ADDRESS, STACK_SIZE)
        mu.reg_write(UC_ARM64_REG_SP, STACK_ADDRESS + STACK_SIZE // 2)
        print(f"    栈: 0x{STACK_ADDRESS:08x} - 0x{STACK_ADDRESS + STACK_SIZE:08x}")
        
        # 映射代码段 - 足够大的空间来容纳所有指令
        CODE_ADDRESS = 0x00000000
        CODE_SIZE = 0x10000000  # 256MB
        mu.mem_map(CODE_ADDRESS, CODE_SIZE)
        print(f"    代码段: 0x{CODE_ADDRESS:08x} - 0x{CODE_ADDRESS + CODE_SIZE:08x}")
        
        # 一次性写入所有段数据
        for seg in self.segments:
            if seg['size'] > 0:
                write_addr = self.load_address + seg['vaddr']
                try:
                    mu.mem_write(write_addr, seg['data'][:seg['size']])
                    flags = ''
                    if seg['is_read']: flags += 'R'
                    if seg['is_write']: flags += 'W'
                    if seg['is_exec']: flags += 'X'
                    print(f"    写入段: 0x{write_addr:08x} [{flags}] size=0x{seg['size']:x}")
                except Exception as e:
                    print(f"    [-] 写入段失败 0x{seg['vaddr']:x}: {e}")
        
        # 如果有data.bin，写入到0x671f20
        if 'data.bin' in self.lib_data:
            data = self.lib_data['data.bin']
            data_address = 0x00671f20
            
            # 确保地址已映射（应该在CODE_ADDRESS范围内）
            if CODE_ADDRESS <= data_address < CODE_ADDRESS + CODE_SIZE:
                try:
                    mu.mem_write(data_address, data)
                    print(f"    data.bin: 写入 {len(data)} 字节到 0x{data_address:08x}")
                except Exception as e:
                    print(f"    [-] 写入data.bin失败: {e}")
            else:
                print(f"    [-] data.bin地址 0x{data_address:08x} 不在映射范围内")
        
        print(f"[+] 内存映射完成")
        
        # 添加内存访问hook（用于调试）
        if enable_hooks:
            def hook_code(uc, address, size, user_data):
                """指令执行hook"""
                # 读取指令字节
                try:
                    code = uc.mem_read(address, size)
                    # 反汇编指令
                    for insn in self.cs.disasm(bytes(code), address):
                        print(f"    [EXEC] 0x{address:08x}: {insn.mnemonic:8s} {insn.op_str}")
                except:
                    print(f"    [EXEC] 0x{address:08x}: (无法反汇编)")
            
            def hook_mem_read(uc, access, address, size, value, user_data):
                """内存读取hook"""
                pc = uc.reg_read(UC_ARM64_REG_PC)
                try:
                    # 读取实际数据
                    data = uc.mem_read(address, size)
                    data_bytes = bytes(data)
                    
                    # 格式化数据显示
                    if size <= 8:
                        # 小数据：显示十六进制值
                        data_int = int.from_bytes(data_bytes, byteorder='little')
                        data_hex = ' '.join(f'{b:02x}' for b in data_bytes)
                        
                        # 尝试解析为ASCII字符串
                        ascii_str = ''
                        if all(32 <= b < 127 or b == 0 for b in data_bytes):
                            ascii_str = ' "' + ''.join(chr(b) if 32 <= b < 127 else '.' for b in data_bytes) + '"'
                        
                        print(f"      [MEM READ] PC=0x{pc:08x} | 地址: 0x{address:08x} | "
                              f"大小: {size}B | 数据: {data_hex} (0x{data_int:x}){ascii_str}")
                    else:
                        # 大数据：只显示前16字节
                        preview = data_bytes[:16]
                        data_hex = ' '.join(f'{b:02x}' for b in preview)
                        suffix = '...' if size > 16 else ''
                        
                        # 如果看起来像字符串，显示ASCII预览
                        ascii_preview = ''
                        if all(32 <= b < 127 or b in (0, 9, 10, 13) for b in preview):
                            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in preview)
                            ascii_preview = f' "{ascii_str}"'
                        
                        print(f"      [MEM READ] PC=0x{pc:08x} | 地址: 0x{address:08x} | "
                              f"大小: {size}B | 数据: {data_hex}{suffix}{ascii_preview}")
                except Exception as e:
                    print(f"      [MEM READ] PC=0x{pc:08x} | 地址: 0x{address:08x} | "
                          f"大小: {size}B | (读取数据失败: {e})")
            
            def hook_mem_write(uc, access, address, size, value, user_data):
                """内存写入hook"""
                pc = uc.reg_read(UC_ARM64_REG_PC)
                try:
                    # 将值转换为字节
                    if size <= 8:
                        value_bytes = value.to_bytes(size, byteorder='little')
                        data_hex = ' '.join(f'{b:02x}' for b in value_bytes)
                        
                        # ASCII表示
                        ascii_str = ''
                        if all(32 <= b < 127 or b == 0 for b in value_bytes):
                            ascii_str = ' "' + ''.join(chr(b) if 32 <= b < 127 else '.' for b in value_bytes) + '"'
                        
                        print(f"      [MEM WRITE] PC=0x{pc:08x} | 地址: 0x{address:08x} | "
                              f"大小: {size}B | 数据: {data_hex} (0x{value:x}){ascii_str}")
                    else:
                        print(f"      [MEM WRITE] PC=0x{pc:08x} | 地址: 0x{address:08x} | "
                              f"大小: {size}B | 值: 0x{value:x}")
                except Exception as e:
                    print(f"      [MEM WRITE] PC=0x{pc:08x} | 地址: 0x{address:08x} | "
                          f"大小: {size}B | 值: 0x{value:x} (解析失败: {e})")
            
            def hook_mem_invalid(uc, access, address, size, value, user_data):
                """无效内存访问hook"""
                pc = uc.reg_read(UC_ARM64_REG_PC)
                access_type = "READ" if access == UC_MEM_READ_UNMAPPED else "WRITE"
                print(f"      [MEM ERROR] PC=0x{pc:08x} | 无效{access_type}: 0x{address:08x} | 大小: {size}")
                return False  # 返回False让模拟器继续（忽略错误）
            
            # 注册hook
            mu.hook_add(UC_HOOK_CODE, hook_code)  # 指令执行hook
            mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
            mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
            mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, 
                       hook_mem_invalid)
            
            print(f"[+] 已启用内存访问追踪hook")
        
        return mu
    
    def find_csel_instructions(self, related_addresses: List[int], 
                               instructions: List[Tuple[int, CsInsn]]) -> List[Tuple[int, str]]:
        """
        在相关指令中查找CSEL等条件选择指令
        
        Args:
            related_addresses: 相关指令地址列表
            instructions: 所有指令
            
        Returns:
            [(地址, 条件码)] 列表，例如 [(0x1234, 'eq'), (0x5678, 'ne')]
        """
        csel_info = []
        insn_dict = {addr: insn for addr, insn in instructions}
        
        for addr in related_addresses:
            if addr in insn_dict:
                insn = insn_dict[addr]
                # 条件选择指令
                if insn.mnemonic.upper() in ['CSEL', 'CSINC', 'CSINV', 'CSNEG']:
                    # 提取条件码（从op_str中解析）
                    # 格式: CSEL X0, X1, X2, EQ  或  csel x0, x1, x2, eq
                    condition = 'unknown'
                    parts = insn.op_str.split(',')
                    if len(parts) >= 4:
                        # 最后一个参数是条件码
                        condition = parts[-1].strip().lower()
                    
                    csel_info.append((addr, condition))
        
        return csel_info
    
    def analyze_function(self, start_offset: int, end_offset: Optional[int] = None,
                        recursion_depth: int = 0, max_depth: int = 3) -> FunctionInfo:
        """
        分析函数
        
        Args:
            start_offset: 起始偏移
            end_offset: 结束偏移
            recursion_depth: 递归深度
            max_depth: 最大递归深度
            
        Returns:
            函数信息
        """
        indent = "  " * recursion_depth
        start_addr = self.offset_to_address(start_offset)
        
        print(f"\n{indent}[*] 分析函数: 0x{start_addr:x} (深度: {recursion_depth})")
        
        # 检查是否已分析
        if start_addr in self.functions:
            print(f"{indent}[*] 函数已分析，跳过")
            return self.functions[start_addr]
        
        # 反汇编
        instructions = self.disassemble_function(start_offset, end_offset)
        
        func_info = FunctionInfo(
            start_address=start_addr,
            end_address=instructions[-1][0] if instructions else None,
            name=f"sub_{start_addr:x}"
        )
        
        # ========== 第一阶段：收集所有间接跳转信息 ==========
        print(f"{indent}[*] 第一阶段：收集间接跳转...")
        jump_info_list = []  # [(idx, addr, insn, target_reg, related_addrs, csel_info)]
        all_related_addrs = set()
        
        for idx, (addr, insn) in enumerate(instructions):
            # 检查间接跳转
            if self.is_indirect_jump(insn):
                print(f"{indent}[!] 发现间接跳转: 0x{addr:x} - {insn.mnemonic} {insn.op_str}")
                
                target_reg = self.get_jump_register(insn)
                if target_reg:
                    # 追踪寄存器依赖
                    related_addrs = self.trace_register_dependencies(instructions, idx, target_reg, debug=False)
                    print(f"{indent}    → {len(related_addrs)} 条相关指令")
                    
                    # 检查是否有条件选择指令
                    csel_info = self.find_csel_instructions(related_addrs, instructions)
                    
                    jump_info_list.append({
                        'idx': idx,
                        'addr': addr,
                        'insn': insn,
                        'target_reg': target_reg,
                        'related_addrs': related_addrs,
                        'csel_info': csel_info
                    })
                    
                    # 汇总所有相关指令
                    all_related_addrs.update(related_addrs)
        
        if not jump_info_list:
            print(f"{indent}[*] 没有发现间接跳转")
            self.functions[start_addr] = func_info
            return func_info
        
        print(f"{indent}[*] 共发现 {len(jump_info_list)} 个间接跳转")
        print(f"{indent}[*] 汇总后共 {len(all_related_addrs)} 条相关指令（去重后）")
        
        # ========== 第二阶段：统一模拟执行 ==========
        print(f"{indent}[*] 第二阶段：创建模拟器...")
        all_related_list = sorted(all_related_addrs)
        
        # 构建需要执行的指令序列（包含相关指令和跳转指令本身，按地址排序）
        # 这样可以在执行到跳转指令时立即读取寄存器
        jump_addrs_set = {info['addr'] for info in jump_info_list}
        all_exec_addrs = sorted(all_related_addrs | jump_addrs_set)
        
        # 寄存器映射
        reg_map = {
            'x0': UC_ARM64_REG_X0, 'x1': UC_ARM64_REG_X1, 'x2': UC_ARM64_REG_X2,
            'x3': UC_ARM64_REG_X3, 'x4': UC_ARM64_REG_X4, 'x5': UC_ARM64_REG_X5,
            'x6': UC_ARM64_REG_X6, 'x7': UC_ARM64_REG_X7, 'x8': UC_ARM64_REG_X8,
            'x9': UC_ARM64_REG_X9, 'x10': UC_ARM64_REG_X10, 'x11': UC_ARM64_REG_X11,
            'x12': UC_ARM64_REG_X12, 'x13': UC_ARM64_REG_X13, 'x14': UC_ARM64_REG_X14,
            'x15': UC_ARM64_REG_X15, 'x16': UC_ARM64_REG_X16, 'x17': UC_ARM64_REG_X17,
            'x18': UC_ARM64_REG_X18, 'x19': UC_ARM64_REG_X19, 'x20': UC_ARM64_REG_X20,
            'x21': UC_ARM64_REG_X21, 'x22': UC_ARM64_REG_X22, 'x23': UC_ARM64_REG_X23,
            'x24': UC_ARM64_REG_X24, 'x25': UC_ARM64_REG_X25, 'x26': UC_ARM64_REG_X26,
            'x27': UC_ARM64_REG_X27, 'x28': UC_ARM64_REG_X28, 'x29': UC_ARM64_REG_X29,
            'x30': UC_ARM64_REG_X30,
        }
        
        # 创建地址到跳转信息的映射
        addr_to_jump_info = {info['addr']: info for info in jump_info_list}
        
        # 分组：有CSEL的和没有CSEL的
        has_csel = any(info['csel_info'] for info in jump_info_list)
        
        if has_csel:
            print(f"{indent}[*] 检测到条件跳转，需要模拟两次")
            # 模拟两次：true和false
            for condition_state in ['true', 'false']:
                print(f"{indent}  [*] 模拟执行（条件={condition_state}）...")
                mu = self.create_emulator(instructions, all_related_list, self.enable_mem_trace)
                
                # Patch所有CSEL指令
                insn_dict = {addr: insn for addr, insn in instructions}
                for info in jump_info_list:
                    if info['csel_info']:
                        for csel_addr, csel_cond in info['csel_info']:
                            if csel_addr in insn_dict:
                                csel_insn = insn_dict[csel_addr]
                                if len(csel_insn.operands) >= 3:
                                    dest_reg = csel_insn.reg_name(csel_insn.operands[0].reg)
                                    true_reg = csel_insn.reg_name(csel_insn.operands[1].reg)
                                    false_reg = csel_insn.reg_name(csel_insn.operands[2].reg)
                                    src_reg = true_reg if condition_state == 'true' else false_reg
                                    
                                    try:
                                        mov_code = f"mov {dest_reg}, {src_reg}"
                                        encoding, count = self.ks.asm(mov_code, csel_addr)
                                        if encoding:
                                            emu_addr = self.load_address + (csel_addr - self.base_address)
                                            mu.mem_write(emu_addr, bytes(encoding))
                                    except:
                                        pass
                
                # 按顺序执行指令，遇到跳转指令时立即读取寄存器
                for addr in all_exec_addrs:
                    try:
                        emu_addr = self.load_address + (addr - self.base_address)
                        mu.emu_start(emu_addr, emu_addr + 4, count=1)
                        
                        # 如果这个地址是跳转指令，立即读取目标寄存器
                        if addr in addr_to_jump_info:
                            info = addr_to_jump_info[addr]
                            target_reg_lower = info['target_reg'].lower()
                            if target_reg_lower in reg_map:
                                value = mu.reg_read(reg_map[target_reg_lower])
                                if condition_state == 'true':
                                    info['target_true'] = value
                                else:
                                    info['target_false'] = value
                    except:
                        pass
        else:
            # 无CSEL，只需模拟一次
            print(f"{indent}[*] 模拟执行...")
            mu = self.create_emulator(instructions, all_related_list, self.enable_mem_trace)
            
            # 按顺序执行指令，遇到跳转指令时立即读取寄存器
            for addr in all_exec_addrs:
                try:
                    emu_addr = self.load_address + (addr - self.base_address)
                    mu.emu_start(emu_addr, emu_addr + 4, count=1)
                    
                    # 如果这个地址是跳转指令，立即读取目标寄存器
                    if addr in addr_to_jump_info:
                        info = addr_to_jump_info[addr]
                        target_reg_lower = info['target_reg'].lower()
                        if target_reg_lower in reg_map:
                            info['target_value'] = mu.reg_read(reg_map[target_reg_lower])
                except:
                    pass
        
        # ========== 第三阶段：生成JumpRecord ==========
        print(f"{indent}[*] 第三阶段：生成跳转记录...")
        for info in jump_info_list:
            # 根据模拟方式获取目标值
            if has_csel:
                # 如果函数中有CSEL，所有跳转都被模拟了两次
                true_target = info.get('target_true')
                false_target = info.get('target_false')
                
                # 检查该跳转是否真的有CSEL
                if info['csel_info']:
                    # 有CSEL的跳转：使用条件分支结果
                    condition = info['csel_info'][0][1] if info['csel_info'] else 'unknown'
                    
                    # 检查两个目标是否相同
                    if true_target == false_target:
                        jump_record = JumpRecord(
                            address=info['addr'],
                            jump_type=JumpType.INDIRECT,
                            target_address=true_target,
                            register=info['target_reg'],
                            related_instructions=info['related_addrs'],
                            condition=condition
                        )
                        print(f"{indent}  [+] 0x{info['addr']:x}: 条件={condition.upper()}, "
                              f"两个分支相同=0x{true_target if true_target else 0:x}")
                    else:
                        jump_record = JumpRecord(
                            address=info['addr'],
                            jump_type=JumpType.INDIRECT,
                            target_address=None,
                            register=info['target_reg'],
                            related_instructions=info['related_addrs'],
                            condition=condition,
                            condition_true=true_target,
                            condition_false=false_target
                        )
                        print(f"{indent}  [+] 0x{info['addr']:x}: 条件={condition.upper()}, "
                              f"true=0x{true_target if true_target else 0:x}, "
                              f"false=0x{false_target if false_target else 0:x}")
                else:
                    # 没有CSEL的跳转：两次模拟结果应该相同，取其一
                    target = true_target if true_target is not None else false_target
                    jump_record = JumpRecord(
                        address=info['addr'],
                        jump_type=JumpType.INDIRECT,
                        target_address=target,
                        register=info['target_reg'],
                        related_instructions=info['related_addrs']
                    )
                    print(f"{indent}  [+] 0x{info['addr']:x}: target=0x{target if target else 0:x}")
            else:
                # 无CSEL的情况：只模拟了一次，使用target_value
                target = info.get('target_value')
                jump_record = JumpRecord(
                    address=info['addr'],
                    jump_type=JumpType.INDIRECT,
                    target_address=target,
                    register=info['target_reg'],
                    related_instructions=info['related_addrs']
                )
                print(f"{indent}  [+] 0x{info['addr']:x}: target=0x{target if target else 0:x}")
            
            func_info.jump_records.append(jump_record)
        
        # ========== 第四阶段：处理递归分析 ==========
        if recursion_depth < max_depth:
            print(f"{indent}[*] 第四阶段：递归分析被调用函数...")
            
            # 收集所有需要递归分析的目标
            targets_to_analyze = set()
            for jump_record in func_info.jump_records:
                # 只对BLR类型递归
                insn_dict = {addr: insn for addr, insn in instructions}
                if jump_record.address in insn_dict:
                    insn = insn_dict[jump_record.address]
                    if insn.mnemonic == 'blr':
                        if jump_record.target_address:
                            targets_to_analyze.add(jump_record.target_address)
                        if jump_record.condition_true:
                            targets_to_analyze.add(jump_record.condition_true)
                        if jump_record.condition_false:
                            targets_to_analyze.add(jump_record.condition_false)
            
            # 递归分析
            for target in targets_to_analyze:
                if self.is_address_in_current_so(target):
                    try:
                        target_offset = self.address_to_offset(target)
                        print(f"{indent}  [*] 递归分析 0x{target:x}...")
                        called_func = self.analyze_function(target_offset, None, recursion_depth + 1, max_depth)
                        func_info.called_functions.add(target)
                    except Exception as e:
                        print(f"{indent}  [-] 递归分析失败 0x{target:x}: {e}")
            
            # 检查直接调用（BL指令）
            for idx, (addr, insn) in enumerate(instructions):
                if insn.mnemonic == 'bl':
                    if len(insn.operands) > 0 and insn.operands[0].type == ARM64_OP_IMM:
                        target = insn.operands[0].imm
                        if self.is_address_in_current_so(target):
                            try:
                                target_offset = self.address_to_offset(target)
                                print(f"{indent}  [*] 递归分析 BL 0x{target:x}...")
                                called_func = self.analyze_function(target_offset, None,
                                                                   recursion_depth + 1, max_depth)
                                func_info.called_functions.add(target)
                            except Exception as e:
                                print(f"{indent}  [-] 递归分析失败: {e}")
        
        self.functions[start_addr] = func_info
        return func_info
    
    def generate_patches(self):
        """生成patch"""
        print(f"\n[*] 生成patch...")
        
        for func_addr, func_info in self.functions.items():
            for jump_record in func_info.jump_records:
                # 下一条指令地址（当前指令 + 4字节）
                next_insn_addr = jump_record.address + 4
                
                # 处理无条件跳转（只有target_address）
                if jump_record.target_address and not jump_record.condition_true and not jump_record.condition_false:
                    # 计算相对偏移
                    offset = jump_record.target_address - jump_record.address
                    
                    # 检查偏移是否在范围内（ARM64 B指令范围：±128MB）
                    if abs(offset) < (1 << 27):
                        try:
                            # 将 BR/BLR 转换为 B/BL
                            if jump_record.jump_type == JumpType.INDIRECT:
                                original_offset = self.address_to_offset(jump_record.address)
                                original_code = self.read_code(original_offset, 4)
                                
                                # 判断原指令类型
                                original_insn = next(self.cs.disasm(original_code, jump_record.address))
                                
                                if original_insn.mnemonic == 'br':
                                    new_mnemonic = 'b'
                                elif original_insn.mnemonic == 'blr':
                                    new_mnemonic = 'bl'
                                else:
                                    continue
                                
                                # 使用keystone汇编新指令
                                asm_code = f"{new_mnemonic} #0x{jump_record.target_address:x}"
                                encoding, count = self.ks.asm(asm_code, jump_record.address)
                                
                                if encoding and len(encoding) == 4:
                                    self.patches[jump_record.address] = bytes(encoding)
                                    # print(f"[+] Patch: 0x{jump_record.address:x}: "
                                    #       f"{original_insn.mnemonic} {original_insn.op_str} -> "
                                    #       f"{new_mnemonic} #0x{jump_record.target_address:x}")
                        except Exception as e:
                            print(f"[-] Patch失败 0x{jump_record.address:x}: {e}")
                
                # 处理条件跳转（有condition_true和condition_false）
                elif jump_record.condition_true or jump_record.condition_false:
                    true_target = jump_record.condition_true
                    false_target = jump_record.condition_false
                    condition = jump_record.condition or 'unknown'
                    
                    # 条件码反转映射
                    inverse_cond = {
                        'eq': 'ne', 'ne': 'eq',
                        'hs': 'lo', 'lo': 'hs',
                        'mi': 'pl', 'pl': 'mi',
                        'vs': 'vc', 'vc': 'vs',
                        'hi': 'ls', 'ls': 'hi',
                        'ge': 'lt', 'lt': 'ge',
                        'gt': 'le', 'le': 'gt',
                    }
                    
                    # 情况1: true分支是下一条指令，只需要跳转false目标（条件为假时跳转）
                    if true_target == next_insn_addr and false_target and false_target != next_insn_addr:
                        inv_cond = inverse_cond.get(condition, 'ne')
                        print(f"[*] 条件跳转 0x{jump_record.address:x}: true分支是下一条指令")
                        print(f"    条件码: {condition.upper()}, 使用反转条件: {inv_cond.upper()}")
                        print(f"    可以patch为: B.{inv_cond.upper()} #0x{false_target:x}")
                        
                        try:
                            asm_code = f"b.{inv_cond} #0x{false_target:x}"
                            encoding, count = self.ks.asm(asm_code, jump_record.address)
                            if encoding and len(encoding) == 4:
                                self.patches[jump_record.address] = bytes(encoding)
                                print(f"    [+] Patch成功")
                        except Exception as e:
                            print(f"    [-] Patch失败: {e}")
                    
                    # 情况2: false分支是下一条指令，只需要跳转true目标（条件为真时跳转）
                    elif false_target == next_insn_addr and true_target and true_target != next_insn_addr:
                        print(f"[*] 条件跳转 0x{jump_record.address:x}: false分支是下一条指令")
                        print(f"    条件码: {condition.upper()}")
                        print(f"    可以patch为: B.{condition.upper()} #0x{true_target:x}")
                        
                        try:
                            asm_code = f"b.{condition} #0x{true_target:x}"
                            encoding, count = self.ks.asm(asm_code, jump_record.address)
                            if encoding and len(encoding) == 4:
                                self.patches[jump_record.address] = bytes(encoding)
                                print(f"    [+] Patch成功")
                        except Exception as e:
                            print(f"    [-] Patch失败: {e}")
                    
                    # 情况3: 两个目标都不是下一条指令
                    elif true_target != next_insn_addr and false_target != next_insn_addr:
                        print(f"[!] 复杂条件跳转 0x{jump_record.address:x}: 两个目标都需要跳转")
                        print(f"    条件为真: 0x{true_target:x}")
                        print(f"    条件为假: 0x{false_target:x}")
                        print(f"    条件码: {condition.upper()}")
                        
                        # 获取related_instructions中的最后一个指令
                        if jump_record.related_instructions:
                            related_addrs = sorted(jump_record.related_instructions)
                            # 找到在BR之前的最后一个相关指令
                            prev_addrs = [addr for addr in related_addrs if addr < jump_record.address]
                            
                            if prev_addrs:
                                prev_insn_addr = prev_addrs[-1]
                                print(f"    [*] 使用最后一个相关指令: 0x{prev_insn_addr:x}")
                                
                                try:
                                    # 读取前序指令（仅用于显示）
                                    prev_offset = self.address_to_offset(prev_insn_addr)
                                    prev_code = self.read_code(prev_offset, 4)
                                    prev_insn = next(self.cs.disasm(prev_code, prev_insn_addr))
                                    print(f"    [*] 前序指令: {prev_insn.mnemonic} {prev_insn.op_str}")
                                    
                                    # 策略: 前序指令 -> B.condition #true_target
                                    #       当前BR -> B #false_target
                                    # 这样：条件成立时跳到true_target，条件不成立时继续执行到BR然后跳到false_target
                                    
                                    asm_code1 = f"b.{condition} #0x{true_target:x}"
                                    encoding1, count1 = self.ks.asm(asm_code1, prev_insn_addr)
                                    
                                    asm_code2 = f"b #0x{false_target:x}"
                                    encoding2, count2 = self.ks.asm(asm_code2, jump_record.address)
                                    
                                    if encoding1 and len(encoding1) == 4 and encoding2 and len(encoding2) == 4:
                                        self.patches[prev_insn_addr] = bytes(encoding1)
                                        self.patches[jump_record.address] = bytes(encoding2)
                                        print(f"    [+] Patch成功:")
                                        print(f"        0x{prev_insn_addr:x}: {prev_insn.mnemonic} {prev_insn.op_str} -> B.{condition.upper()} #0x{true_target:x}")
                                        print(f"        0x{jump_record.address:x}: BR -> B #0x{false_target:x}")
                                    else:
                                        print(f"    [-] Patch失败: 汇编生成失败")
                                except Exception as e:
                                    print(f"    [-] Patch失败: {e}")
                            else:
                                print(f"    [警告] 未找到BR之前的相关指令，无法patch")
                        else:
                            print(f"    [警告] 没有相关指令记录，无法patch")
                    
                    # 情况4: 两个目标相同（虽然前面逻辑会合并到default，但以防万一）
                    elif true_target == false_target:
                        print(f"[*] 条件跳转 0x{jump_record.address:x}: 两个分支目标相同")
                        print(f"    可以patch为无条件跳转: B #0x{true_target:x}")
                    
                    else:
                        print(f"[?] 未知条件跳转情况 0x{jump_record.address:x}")
                        print(f"    条件为真: {hex(true_target) if true_target else 'None'}")
                        print(f"    条件为假: {hex(false_target) if false_target else 'None'}")
        
        print(f"[*] 共生成 {len(self.patches)} 个patch")
    
    def apply_patches(self, output_path: str):
        """应用patch并保存"""
        
        patched_data = bytearray(self.so_data)
        
        for addr, patch_bytes in self.patches.items():
            offset = self.address_to_offset(addr)
            if 0 <= offset < len(patched_data):
                patched_data[offset:offset + len(patch_bytes)] = patch_bytes
        
        # 保存
        with open(output_path, 'wb') as f:
            f.write(patched_data)
        
        print(f"[+] Patch后的文件已保存: {output_path}")
    
    def save_analysis_report(self, output_path: str):
        """保存分析报告"""
        print(f"\n[*] 生成分析报告...")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("ARM64反混淆分析报告\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"SO文件: {self.so_path}\n")
            f.write(f"基址: 0x{self.base_address:x}\n")
            f.write(f"分析函数数: {len(self.functions)}\n")
            f.write(f"Patch数: {len(self.patches)}\n\n")
            
            for func_addr, func_info in sorted(self.functions.items()):
                f.write(f"\n{'='*80}\n")
                f.write(f"函数: {func_info.name} @ 0x{func_addr:x}\n")
                f.write(f"{'='*80}\n\n")
                
                if func_info.jump_records:
                    f.write("间接跳转记录:\n")
                    f.write("-" * 80 + "\n")
                    
                    for jr in func_info.jump_records:
                        f.write(f"\n地址: 0x{jr.address:x}\n")
                        f.write(f"类型: {jr.jump_type.name}\n")
                        f.write(f"寄存器: {jr.register}\n")
                        f.write(f"目标: 0x{jr.target_address:x}\n" if jr.target_address else "目标: 未知\n")
                        
                        if jr.related_instructions:
                            f.write(f"相关指令 ({len(jr.related_instructions)}条):\n")
                            for rel_addr in jr.related_instructions:
                                f.write(f"  - 0x{rel_addr:x}\n")
                        f.write("\n")
                
                if func_info.called_functions:
                    f.write("调用的函数:\n")
                    f.write("-" * 80 + "\n")
                    for called_addr in sorted(func_info.called_functions):
                        f.write(f"  - 0x{called_addr:x}\n")
                    f.write("\n")
        
        print(f"[+] 分析报告已保存: {output_path}")


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='ARM64反混淆工具 - 分析间接跳转并自动生成patch',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 基本用法
  python arm64_deobfuscator.py libnative.so 0x1000
  
  # 启用调试追踪
  python arm64_deobfuscator.py libnative.so 0x1000 --trace-mem
  
  # 完整示例
  python arm64_deobfuscator.py app.so 0x2DA014 \\
      --max-depth 5 \\
      -o patched.so \\
      -r report.txt

注意：如果需要在0x671f20位置加载数据，请将数据保存为当前目录下的data.bin文件
        """
    )
    
    parser.add_argument('so_file', help='ARM64 SO文件路径')
    parser.add_argument('offset', help='函数起始偏移 (十六进制，如: 0x1000)')
    parser.add_argument('--end', help='函数结束偏移 (十六进制，可选)', default=None)
    parser.add_argument('--output', '-o', help='输出文件路径', default=None)
    parser.add_argument('--report', '-r', help='分析报告路径', default=None)
    parser.add_argument('--max-depth', type=int, default=3, help='最大递归深度 (默认: 3)')
    parser.add_argument('--trace-mem', action='store_true', help='启用内存访问追踪（调试用）')
    
    args = parser.parse_args()
    
    # 解析偏移
    try:
        start_offset = int(args.offset, 16) if args.offset.startswith('0x') else int(args.offset)
    except ValueError:
        print(f"错误: 无效的偏移地址: {args.offset}")
        return 1
    
    end_offset = None
    if args.end:
        try:
            end_offset = int(args.end, 16) if args.end.startswith('0x') else int(args.end)
        except ValueError:
            print(f"错误: 无效的结束地址: {args.end}")
            return 1
    
    # 设置输出路径
    if not args.output:
        base_name = os.path.splitext(args.so_file)[0]
        args.output = f"{base_name}_patched.so"
    
    if not args.report:
        base_name = os.path.splitext(args.so_file)[0]
        args.report = f"{base_name}_report.txt"
    
    print("ARM64反混淆工具")
    print("=" * 80)
    
    try:
        # 创建分析器
        analyzer = ARM64Analyzer(args.so_file, enable_mem_trace=args.trace_mem)
        
        if args.trace_mem:
            print("[*] 已启用内存访问追踪模式")
        
        # 分析函数
        analyzer.analyze_function(start_offset, end_offset, max_depth=args.max_depth)
        
        # 生成patch
        analyzer.generate_patches()
        
        # 应用patch
        analyzer.apply_patches(args.output)
        
        # 保存报告
        analyzer.save_analysis_report(args.report)
        
        print("\n" + "=" * 80)
        print("[+] 分析完成!")
        print(f"[+] Patch文件: {args.output}")
        print(f"[+] 分析报告: {args.report}")
        
        return 0
        
    except Exception as e:
        print(f"\n[-] 错误: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())

