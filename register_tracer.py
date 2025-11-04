#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARM64汇编寄存器依赖追踪器
功能：从一个寄存器指令向上递归追踪所有参与赋值的指令，直到找到静态赋值指令
"""

import re
from typing import Set, List, Dict, Tuple
from dataclasses import dataclass


@dataclass
class Instruction:
    """指令数据结构"""
    line_num: int
    address: str
    opcode: str
    operands: str
    full_line: str


class RegisterTracer:
    """寄存器依赖追踪器"""
    
    def __init__(self, instructions: List[Instruction]):
        self.instructions = instructions
        self.visited_pairs: Set[Tuple[str, int]] = set()  # (寄存器, 开始行号)
        self.result_instructions: List[Instruction] = []
        
    @staticmethod
    def parse_instruction_line(line: str, line_num: int) -> Instruction:
        """解析一条汇编指令"""
        # 匹配格式: .text:地址 指令 操作数
        pattern = r'\.text:([0-9A-Fa-f]+)\s+(\w+)\s+(.+?)(?:\s*;.*)?$'
        match = re.match(pattern, line.strip())
        
        if match:
            address = match.group(1)
            opcode = match.group(2)
            operands = match.group(3).strip()
            return Instruction(line_num, address, opcode, operands, line)
        return None
    
    @staticmethod
    def normalize_register(reg: str) -> str:
        """标准化寄存器名称（X和W寄存器映射）"""
        reg = reg.upper().strip()
        # 移除可能的前缀符号
        reg = reg.lstrip('#')
        
        # W寄存器映射到对应的X寄存器
        if reg.startswith('W'):
            try:
                num = int(reg[1:])
                return f'X{num}'
            except:
                pass
        
        return reg
    
    def get_destination_register(self, inst: Instruction) -> str:
        """获取指令的目标寄存器"""
        opcode = inst.opcode.upper()
        
        # 存储指令（不修改寄存器）
        store_ops = {'STR', 'STUR', 'STP', 'STRB', 'STRH'}
        if opcode in store_ops:
            return None
        
        # 分支和比较指令
        branch_ops = {'B', 'BR', 'BL', 'BLR', 'CMP', 'CMN', 'TST'}
        if opcode in branch_ops:
            return None
        
        # 获取第一个操作数（通常是目标寄存器）
        operands = inst.operands.split(',')
        if operands:
            dest = operands[0].strip()
            # 处理内存访问模式 [X1, #0x10]
            if '[' not in dest and ']' not in dest:
                return self.normalize_register(dest)
        
        return None
    
    def get_source_registers(self, inst: Instruction) -> Set[str]:
        """获取指令的源寄存器"""
        opcode = inst.opcode.upper()
        sources = set()
        
        # 特殊处理某些指令
        if opcode in {'MRS'}:
            # MRS读取系统寄存器，不是普通寄存器
            return sources
        
        operands = inst.operands.split(',')
        
        # 存储指令：第一个是源寄存器，后面是地址
        if opcode in {'STR', 'STUR', 'STRB', 'STRH'}:
            if len(operands) > 0:
                sources.add(self.normalize_register(operands[0].strip()))
            # 解析地址中的寄存器
            if len(operands) > 1:
                addr = ','.join(operands[1:])
                sources.update(self.extract_registers_from_operand(addr))
            return sources
        
        # STP: 两个源寄存器
        if opcode == 'STP':
            if len(operands) >= 2:
                sources.add(self.normalize_register(operands[0].strip()))
                sources.add(self.normalize_register(operands[1].strip()))
            if len(operands) > 2:
                addr = ','.join(operands[2:])
                sources.update(self.extract_registers_from_operand(addr))
            return sources
        
        # 分支指令
        if opcode in {'BR', 'BLR'}:
            if len(operands) > 0:
                sources.add(self.normalize_register(operands[0].strip()))
            return sources
        
        # 比较指令
        if opcode in {'CMP', 'CMN', 'TST'}:
            for op in operands:
                sources.update(self.extract_registers_from_operand(op))
            return sources
        
        # 一般指令：跳过第一个操作数（目标），后面都是源
        for i, op in enumerate(operands):
            if i == 0:
                continue  # 跳过目标寄存器
            sources.update(self.extract_registers_from_operand(op))
        
        return sources
    
    def extract_registers_from_operand(self, operand: str) -> Set[str]:
        """从操作数中提取所有寄存器"""
        registers = set()
        
        # 匹配X或W寄存器
        pattern = r'\b([XW]\d+)\b'
        matches = re.findall(pattern, operand.upper())
        
        for reg in matches:
            registers.add(self.normalize_register(reg))
        
        return registers
    
    def is_static_assignment(self, inst: Instruction) -> bool:
        """判断是否为静态赋值指令（不依赖其他寄存器的值）"""
        opcode = inst.opcode.upper()
        
        # MOV指令：如果操作数是立即数或特殊寄存器，则是静态的
        if opcode in {'MOV', 'MOVZ', 'MOVN'}:
            operands = inst.operands.split(',')
            if len(operands) >= 2:
                second_op = operands[1].strip()
                # 如果第二个操作数是立即数或WZR/XZR
                if second_op.startswith('#') or second_op.upper() in {'WZR', 'XZR'}:
                    return True
        
        # MOVK: 修改寄存器的部分位，依赖寄存器原有值，不是完全静态
        # 但如果之前已经追踪过该寄存器的MOV，可以停止
        if opcode == 'MOVK':
            return False  # 需要继续追踪之前的赋值
        
        # ADRP: 加载页地址（可视为静态）
        if opcode == 'ADRP':
            return True
        
        # ADR: 加载地址
        if opcode == 'ADR':
            return True
        
        return False
    
    def is_initial_value_instruction(self, inst: Instruction) -> bool:
        """判断是否为初始赋值指令（MOV立即数，不是MOVK）"""
        opcode = inst.opcode.upper()
        if opcode in {'MOV', 'MOVZ', 'MOVN'}:
            operands = inst.operands.split(',')
            if len(operands) >= 2:
                second_op = operands[1].strip()
                if second_op.startswith('#') or second_op.upper() in {'WZR', 'XZR'}:
                    return True
        if opcode == 'ADRP':
            return True
        return False
    
    def trace_register(self, target_reg: str, start_line: int) -> None:
        """
        从指定行向上追踪目标寄存器的定义
        
        Args:
            target_reg: 要追踪的寄存器
            start_line: 开始搜索的行号
        """
        target_reg = self.normalize_register(target_reg)
        
        # 避免重复追踪相同的(寄存器, 起始位置)
        trace_key = (target_reg, start_line)
        if trace_key in self.visited_pairs:
            return
        
        self.visited_pairs.add(trace_key)
        
        # 从start_line向上查找
        for i in range(start_line - 1, -1, -1):
            inst = self.instructions[i]
            if inst is None:
                continue
            
            dest_reg = self.get_destination_register(inst)
            
            # 找到定义目标寄存器的指令
            if dest_reg == target_reg:
                # 记录这条指令
                self.result_instructions.append(inst)
                
                # 获取源寄存器并递归追踪
                source_regs = self.get_source_registers(inst)
                for src_reg in source_regs:
                    self.trace_register(src_reg, i)
                
                # 如果是初始赋值指令（MOV立即数、ADRP等），停止追踪
                if self.is_initial_value_instruction(inst):
                    break
                
                # 如果是MOVK，继续向上找该寄存器的前续赋值（MOV）
                opcode = inst.opcode.upper()
                if opcode == 'MOVK':
                    # 不break，继续向上查找
                    continue
                
                # 其他情况停止向上搜索
                break
    
    def trace_from_instruction(self, line_num: int) -> List[Instruction]:
        """
        从指定行的指令开始追踪
        
        Args:
            line_num: 指令行号（从1开始）
            
        Returns:
            所有相关的指令列表，按照执行顺序排序
        """
        if line_num < 1 or line_num > len(self.instructions):
            raise ValueError(f"无效的行号: {line_num}")
        
        inst = self.instructions[line_num - 1]
        if inst is None:
            raise ValueError(f"第{line_num}行不是有效的指令")
        
        # 获取起始指令使用的寄存器
        source_regs = self.get_source_registers(inst)
        
        # 追踪每个寄存器
        for reg in source_regs:
            self.trace_register(reg, line_num)
        
        # 按行号排序结果
        self.result_instructions.sort(key=lambda x: x.line_num)
        
        return self.result_instructions
    
    def print_trace_result(self, start_inst: Instruction) -> None:
        """打印追踪结果"""
        print(f"\n{'='*80}")
        print(f"追踪起始指令（第{start_inst.line_num}行）:")
        print(f"  {start_inst.full_line.strip()}")
        print(f"\n相关指令追踪结果（共{len(self.result_instructions)}条）:")
        print(f"{'='*80}\n")
        
        for inst in self.result_instructions:
            is_static = self.is_static_assignment(inst)
            dest = self.get_destination_register(inst)
            sources = self.get_source_registers(inst)
            
            print(f"第{inst.line_num}行: {inst.full_line.strip()}")
            print(f"  目标寄存器: {dest}")
            print(f"  源寄存器: {sources if sources else '无'}")
            print(f"  静态赋值: {'是' if is_static else '否'}")
            print()
    
    def print_instructions_only(self) -> None:
        """只打印指令列表，不包含分析信息"""
        print(f"\n{'='*80}")
        print(f"涉及到的所有指令（共{len(self.result_instructions)}条）:")
        print(f"{'='*80}\n")
        
        for inst in self.result_instructions:
            print(inst.full_line.strip())
        
        print(f"\n{'='*80}")
        print("指令编号列表:")
        print(f"{'='*80}\n")
        
        line_numbers = [inst.line_num for inst in self.result_instructions]
        print(f"行号: {line_numbers}")
        print(f"总计: {len(line_numbers)} 条指令")


def load_assembly_file(filename: str) -> List[Instruction]:
    """加载汇编文件并解析指令"""
    instructions = []
    
    with open(filename, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            inst = RegisterTracer.parse_instruction_line(line, line_num)
            instructions.append(inst)
    
    return instructions


def main():
    """主函数"""
    # 加载汇编文件
    filename = 'sample.txt'
    print(f"正在加载文件: {filename}")
    
    instructions = load_assembly_file(filename)
    print(f"共加载 {len(instructions)} 行")
    
    # 创建追踪器
    tracer = RegisterTracer(instructions)
    
    # 追踪第58行的BR X3指令
    target_line = 58
    print(f"\n开始追踪第 {target_line} 行的指令...")
    
    try:
        start_inst = instructions[target_line - 1]
        result = tracer.trace_from_instruction(target_line)
        
        # 打印详细的追踪结果
        tracer.print_trace_result(start_inst)
        
        # 生成依赖图
        print(f"{'='*80}")
        print("寄存器依赖关系:")
        print(f"{'='*80}\n")
        
        for inst in result:
            dest = tracer.get_destination_register(inst)
            sources = tracer.get_source_registers(inst)
            if dest and sources:
                print(f"{dest} ← {sources} (第{inst.line_num}行)")
        
        # 打印简洁的指令列表
        tracer.print_instructions_only()
        
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()

