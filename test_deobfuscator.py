#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARM64反混淆工具测试脚本
"""

import os
import sys

def test_sample():
    """测试sample.txt的分析"""
    print("="*80)
    print("测试: 使用sample.txt作为输入")
    print("="*80)
    
    # 注意：这个测试需要有一个实际的ARM64 SO文件
    # sample.txt只是汇编代码文本，不是二进制文件
    
    print("\n提示：")
    print("1. sample.txt是汇编代码文本，不能直接用于反混淆")
    print("2. 需要一个实际的ARM64 SO二进制文件")
    print("3. 可以使用以下命令测试实际的SO文件：")
    print()
    print("   python arm64_deobfuscator.py <your_so_file> 0x2DA014")
    print()

def create_test_so():
    """创建一个简单的测试SO文件（演示）"""
    print("="*80)
    print("创建测试SO文件示例")
    print("="*80)
    
    print("\n要创建测试SO文件，你需要：")
    print()
    print("1. 准备ARM64汇编代码：")
    print("""
    .text
    .global test_func
    test_func:
        // 间接跳转示例
        MOV X3, #0x1234
        MOVK X3, #0x5678, LSL#16
        BR X3
    """)
    
    print("\n2. 使用ARM64工具链编译：")
    print("""
    aarch64-linux-gnu-as -o test.o test.s
    aarch64-linux-gnu-ld -shared -o test.so test.o
    """)
    
    print("\n3. 使用反混淆工具：")
    print("""
    python arm64_deobfuscator.py test.so 0x0
    """)

def demo_usage():
    """演示用法"""
    print("="*80)
    print("ARM64反混淆工具 - 使用演示")
    print("="*80)
    
    examples = [
        {
            "title": "基本用法",
            "desc": "分析从偏移0x1000开始的函数",
            "cmd": "python arm64_deobfuscator.py libnative.so 0x1000"
        },
        {
            "title": "指定结束地址",
            "desc": "只分析特定范围",
            "cmd": "python arm64_deobfuscator.py libnative.so 0x1000 --end 0x2000"
        },
        {
            "title": "深度递归分析",
            "desc": "分析所有调用链",
            "cmd": "python arm64_deobfuscator.py libnative.so 0x1000 --max-depth 5"
        },
        {
            "title": "自定义输出",
            "desc": "指定输出文件名",
            "cmd": "python arm64_deobfuscator.py libnative.so 0x1000 -o clean.so -r report.txt"
        }
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"\n示例 {i}: {example['title']}")
        print(f"描述: {example['desc']}")
        print(f"命令: {example['cmd']}")
        print()

def analyze_sample_instructions():
    """分析sample.txt中的指令模式"""
    print("="*80)
    print("分析sample.txt中的混淆模式")
    print("="*80)
    
    if not os.path.exists('sample.txt'):
        print("\n错误: 找不到sample.txt")
        return
    
    print("\n分析结果：")
    print()
    
    with open('sample.txt', 'r') as f:
        lines = f.readlines()
    
    # 查找间接跳转
    indirect_jumps = []
    for i, line in enumerate(lines, 1):
        if 'BR ' in line or 'BLR ' in line:
            indirect_jumps.append((i, line.strip()))
    
    if indirect_jumps:
        print(f"发现 {len(indirect_jumps)} 个间接跳转：")
        for line_num, instruction in indirect_jumps:
            print(f"  第{line_num}行: {instruction}")
        print()
        
        # 分析第一个间接跳转
        if indirect_jumps:
            line_num, instruction = indirect_jumps[0]
            print(f"分析第{line_num}行的间接跳转：")
            print(f"  指令: {instruction}")
            
            # 提取寄存器
            import re
            match = re.search(r'BR\s+(\w+)', instruction)
            if match:
                reg = match.group(1)
                print(f"  使用寄存器: {reg}")
                print(f"  需要追踪: 所有给{reg}赋值的指令")
                
                # 简单向上查找
                print(f"\n  向上查找{reg}的赋值：")
                for j in range(line_num - 1, max(0, line_num - 50), -1):
                    if reg in lines[j] and any(op in lines[j] for op in ['MOV', 'ADD', 'LDR']):
                        print(f"    第{j}行: {lines[j].strip()}")
    else:
        print("未发现间接跳转")
    
    # 查找MOVK序列（立即数组装）
    print("\n立即数组装模式：")
    movk_sequences = {}
    for i, line in enumerate(lines, 1):
        if 'MOVK' in line:
            match = re.search(r'MOVK\s+(\w+)', line)
            if match:
                reg = match.group(1)
                if reg not in movk_sequences:
                    movk_sequences[reg] = []
                movk_sequences[reg].append((i, line.strip()))
    
    for reg, instructions in movk_sequences.items():
        if len(instructions) > 1:
            print(f"\n  寄存器{reg}的MOVK序列 ({len(instructions)}条):")
            for line_num, instruction in instructions:
                print(f"    第{line_num}行: {instruction}")

def main():
    """主函数"""
    print("\nARM64反混淆工具 - 测试套件\n")
    
    menu = """
选择测试选项:
1. 查看使用演示
2. 分析sample.txt中的混淆模式
3. 查看创建测试SO的方法
4. 运行完整测试（需要实际SO文件）
0. 退出

请选择: """
    
    while True:
        try:
            choice = input(menu).strip()
            
            if choice == '0':
                print("\n再见!")
                break
            elif choice == '1':
                demo_usage()
            elif choice == '2':
                analyze_sample_instructions()
            elif choice == '3':
                create_test_so()
            elif choice == '4':
                test_sample()
            else:
                print("\n无效选择，请重试")
            
            input("\n按Enter继续...")
            print("\n" * 2)
            
        except KeyboardInterrupt:
            print("\n\n中断退出")
            break
        except Exception as e:
            print(f"\n错误: {e}")

if __name__ == '__main__':
    main()

