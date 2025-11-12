#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from unicorn import *
from unicorn.arm64_const import *
import struct
import os
import traceback
# from udbserver import udbserver

# 定义内存映射的地址 - 使用更合适的地址空间
BASE_ADDR = 0xcbbcb000  # libcore.so的加载地址（避免使用0地址）
STACK_ADDR = 0x70000000  # 栈地址
STACK_SIZE = 0x100000  # 减小栈大小
DATA_ADDR_1 = 0x80000000  # 第一个数据缓冲区地址
DATA_ADDR_2 = 0x81000000  # 第二个数据缓冲区地址
POINTER_ADDR = 0x82000000  # 指针缓冲区地址

# 从输入.txt中提取的数据
x0_data_hex = [
    "1491135391d8aad2d70a5b93ce59ac92",
    "cdb7d45b094309b1dd234278c926a5cf",
    "602df62d774912d688044a7cf07e734d",
    "999fdbdf8dc8579b07b05f6685a18703",
    "a11b4e25ab2058926d7b1f9d078c169a",
    "ac386b5dc051770ff36b474fecf8f01f",
    "d9621b446402595fd2d58abb6a057ae0",
    "e5f23ec15252507e2e0671275ae0db36",
    "174f23dcdc21376af8a2827616689cc6",
    "5dcbc8dfe6b6982fd86d8e90c6b51933",
    "449da56928fd6776e1b781b8488b12f3",
    "c198636e422cb873006e5c3c89c5198f",
    "80883a2a67efad93f90a7c40337ab353",
    "72e5e95720c2329caf7599bf1dbc97d3",
    "c41ee4f1308bfc38c5d02a94ea84568d",
    "0ed4c0e327daa8aac2a981542b0384e8"
]

X1_data_hex = [
    "032a796e8d9063697c958af161b0b47c",
    "6356d4578ae66543f497b6a4b5bab812",
    "7b784d724de6351c116ebf6ab4951d03",
    "57d724a7e8f67b9cfed3d756806ade24",
    "834ae8e47d7728f2fdd3f219b0795deb",
    "8e97763ac47918c5e69f0e52f5695eb0",
    "a94da9fd488c3c33a5886f6d2e6d699d"
]

# 转换hex字符串为字节数据
def hex_to_bytes(hex_list):
    result = b"".join(bytes.fromhex(hex_str) for hex_str in hex_list)
    return result

# 读取libcore.so文件
def read_libcore_so(file_path):
    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"无法读取libcore.so文件: {e}")
        return None

# 初始化unicorn引擎并执行模拟
def emulate_libcore_function():
    mu = None
    try:
        # 创建Unicorn引擎实例 (ARM64)
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        
        # 读取libcore.so文件
        libcore_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "libcore.bin")
        libcore_data = read_libcore_so(libcore_path)
        
        if not libcore_data:
            print("无法继续，缺少libcore.so文件")
            return
        
        
        # 映射内存 - 使用更大的内存块并确保地址对齐
        print("映射内存...")
        try:
            # 确保内存块大小是4K对齐的
            lib_size = (len(libcore_data) + 0x10000 + 0xFFF) & ~0xFFF
            mu.mem_map(BASE_ADDR, lib_size, UC_PROT_ALL)
            print(f"映射libcore.so内存 @ 0x{BASE_ADDR:x}, 大小: 0x{lib_size:x}")
            
            mu.mem_map(STACK_ADDR, STACK_SIZE, UC_PROT_ALL)
            print(f"映射栈内存 @ 0x{STACK_ADDR:x}, 大小: 0x{STACK_SIZE:x}")
            
            mu.mem_map(DATA_ADDR_1, 0x10000, UC_PROT_ALL)
            print(f"映射数据内存1 @ 0x{DATA_ADDR_1:x}")
            
            mu.mem_map(DATA_ADDR_2, 0x10000, UC_PROT_ALL)
            print(f"映射数据内存2 @ 0x{DATA_ADDR_2:x}")
            
            mu.mem_map(POINTER_ADDR, 0x10000, UC_PROT_ALL)
            print(f"映射指针内存 @ 0x{POINTER_ADDR:x}")
        except UcError as e:
            print(f"内存映射失败: {e} [初始化阶段]")
            return
        
        # 加载libcore.so到内存
        print("将libcore.so加载到内存...")
        mu.mem_write(BASE_ADDR, libcore_data)
        print("libcore.so加载完成")
        

        # 准备数据
        print("准备数据...")
        x0_data = hex_to_bytes(x0_data_hex)
        X1_data = hex_to_bytes(X1_data_hex)
        print(f"x0数据大小: {len(x0_data)} 字节")
        print(f"X1数据大小: {len(X1_data)} 字节")
        
        # 将数据写入内存
        print("将数据写入内存...")
        mu.mem_write(DATA_ADDR_1, x0_data)
        mu.mem_write(DATA_ADDR_2, X1_data)
        
        # 设置指针链：POINTER_ADDR -> DATA_ADDR_2
        print("设置指针链...")
        mu.mem_write(POINTER_ADDR, struct.pack("<Q", DATA_ADDR_2))
        
        # 设置寄存器
        print("设置寄存器...")
        mu.reg_write(UC_ARM64_REG_X0, DATA_ADDR_1)  # x0指向第一个数据
        mu.reg_write(UC_ARM64_REG_X1, POINTER_ADDR)  # X1指向指针，该指针指向第二个数据
        mu.reg_write(UC_ARM64_REG_SP, STACK_ADDR + STACK_SIZE - 16)  # 设置栈指针
        
        # 验证寄存器设置
        x0_val = mu.reg_read(UC_ARM64_REG_X0)
        X1_val = mu.reg_read(UC_ARM64_REG_X1)
        sp_val = mu.reg_read(UC_ARM64_REG_SP)
        print(f"寄存器设置验证:")
        print(f"  x0: 0x{x0_val:x}")
        print(f"  X1: 0x{X1_val:x}")
        print(f"  sp: 0x{sp_val:x}")
        
        # 模拟执行的函数地址
        function_addr = BASE_ADDR + 0x2d050c
        function_end_addr = BASE_ADDR + 0x2D0A38
        print(f"函数地址: 0x{function_addr:x}")
        
        # 设置一个简单的返回地址（函数执行完后跳到这里）
        return_addr = BASE_ADDR + 0x2d01f0 # 增加距离以避免冲突
        print(f"返回地址: 0x{return_addr:x}")
        
        # 在栈上压入返回地址
        print("在栈上压入返回地址...")
        mu.mem_write(STACK_ADDR + STACK_SIZE - 16, struct.pack("<Q", return_addr))
        
        # 添加内存访问钩子，但只在关键地址附近输出
        def hook_mem_access(uc, access, address, size, value, user_data):
            # 只监控关键地址范围的访问
            if (BASE_ADDR - 0x1000 <= address <= BASE_ADDR + len(libcore_data) + 0x1000 or
                DATA_ADDR_1 - 0x100 <= address <= DATA_ADDR_1 + 0x1000 or
                DATA_ADDR_2 - 0x100 <= address <= DATA_ADDR_2 + 0x1000):
                offset = uc.reg_read(UC_ARM64_REG_PC) - BASE_ADDR
                if access == UC_MEM_WRITE:
                    print(f" 偏移0x{offset:x} 关键内存写入: 0x{address:x}, 大小: {size}, 值: 0x{value:x}")
                elif access == UC_MEM_READ:
                    #如果地址不是0x8开头的就忽略
                    if not hex(address).startswith("0x8"):
                        return
                    value = mu.mem_read(address, size).hex()
                    
                    print(f" 偏移0x{offset:x} 关键内存读取: 0x{address:x}, 大小: {size}, 值: 0x{value}")
        
        # 添加内存错误钩子 - 使用更简单的错误处理方式
        def hook_mem_error(uc, access, address, size, value, user_data):
            # 获取当前执行位置
            try:
                current_pc = uc.reg_read(UC_ARM64_REG_PC)
                pc_info = f" [执行位置: 0x{current_pc:x}]"
            except:
                pc_info = " [无法获取执行位置]"
            
            # 只输出重要的内存错误信息
            if address > 0x100000000:  # 过滤掉明显无效的地址
                print(f"内存错误: 访问无效地址 0x{address:x}{pc_info}")
                # 对于读取错误，我们可以尝试提供一个默认值
                if access == UC_MEM_READ_UNMAPPED:
                    return True  # 继续执行，让Unicorn使用默认值
            else:
                print(f"内存错误: 访问类型: {access}, 地址: 0x{address:x}, 大小: {size}{pc_info}")
            return False  # 对于其他错误，让它抛出异常以便我们可以捕获并处理
        
        # 定义地址钩子函数，用于在特定地址记录寄存器值
        def hook_code(uc, address, size, user_data):
            # 计算相对于BASE_ADDR的偏移量
            offset = address - BASE_ADDR
            
            # 检查是否是我们需要hook的地址
            # if offset >= 0x2d0930 and offset < 0x2d09f0:
            #     # 读取q0寄存器的值
            #     q0_val = uc.reg_read(UC_ARM64_REG_Q0)
            #     q1_val = uc.reg_read(UC_ARM64_REG_Q1)
            #     q2_val = uc.reg_read(UC_ARM64_REG_Q2)
            #     q3_val = uc.reg_read(UC_ARM64_REG_Q3)

            #     # 以little_endian_hex方式打印寄存器值
            #     q0_le = q0_val.to_bytes(16, byteorder='little').hex()
            #     q1_le = q1_val.to_bytes(16, byteorder='little').hex()
            #     q2_le = q2_val.to_bytes(16, byteorder='little').hex()
            #     q3_le = q3_val.to_bytes(16, byteorder='little').hex()
            #     print(f"在偏移0x{offset:x}处: q0 = 0x{q0_le}, q1 = 0x{q1_le}, q2 = 0x{q2_le}, q3 = 0x{q3_le}")
            if offset > 0x2D09B4 and offset < 0x2D09F0:
                print(f"在偏移0x{offset:x}处: w9 = 0x{mu.reg_read(UC_ARM64_REG_W9):x},w10 = 0x{mu.reg_read(UC_ARM64_REG_W10):x},w11 = 0x{mu.reg_read(UC_ARM64_REG_W11):x},w12 = 0x{mu.reg_read(UC_ARM64_REG_W12):x}")
            if offset == 0x2D0934:
                 print(f"在偏移0x{offset:x}处: w9 = 0x{mu.reg_read(UC_ARM64_REG_W9):x}")
        # 添加钩子
        print("添加调试钩子...")
        mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access)
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_error)
        # 添加代码执行钩子
        mu.hook_add(UC_HOOK_CODE, hook_code)
        
        print(f"目标地址: 0x{return_addr:x}")
        
        try:
            # udbserver(mu, 1234, BASE_ADDR+0x2D05DC)
            # 简化执行策略，只执行有限数量的指令
            print("开始执行函数...")

            mu.emu_start(function_addr, function_end_addr)  
            print("函数执行完成")
            
            # 读取结果（假设结果在x0寄存器中）
            result = mu.reg_read(UC_ARM64_REG_X0)
            print(f"函数返回值 (x0): 0x{result:x}")
            
            print("模拟执行完成")
            
        except UcError as e:
            # 尝试获取执行位置信息
            try:
                current_pc = mu.reg_read(UC_ARM64_REG_PC)
                pc_info = f" [执行位置: 0x{current_pc:x}]"
            except:
                pc_info = " [无法获取执行位置]"
            
            print(f"模拟执行出错: {e}{pc_info}")
            
            # 尝试获取关键调试信息
            print("\n执行结果摘要:")
            try:
                # 读取所有重要寄存器
                regs = {
                    "PC": mu.reg_read(UC_ARM64_REG_PC),
                    "SP": mu.reg_read(UC_ARM64_REG_SP),
                    "X0": mu.reg_read(UC_ARM64_REG_X0),
                    "X1": mu.reg_read(UC_ARM64_REG_X1),
                    "X2": mu.reg_read(UC_ARM64_REG_X2),
                    "X3": mu.reg_read(UC_ARM64_REG_X3),
                    "X4": mu.reg_read(UC_ARM64_REG_X4),
                    "X5": mu.reg_read(UC_ARM64_REG_X5),
                    "X6": mu.reg_read(UC_ARM64_REG_X6),
                    "X7": mu.reg_read(UC_ARM64_REG_X7),
                    "X8": mu.reg_read(UC_ARM64_REG_X8),
                    "X9": mu.reg_read(UC_ARM64_REG_X9),
                    "X10": mu.reg_read(UC_ARM64_REG_X10),
                    "X11": mu.reg_read(UC_ARM64_REG_X11),
                    "X12": mu.reg_read(UC_ARM64_REG_X12),
                    "X13": mu.reg_read(UC_ARM64_REG_X13),
                    "X14": mu.reg_read(UC_ARM64_REG_X14),
                    "X15": mu.reg_read(UC_ARM64_REG_X15),
                    "X16": mu.reg_read(UC_ARM64_REG_X16),
                    "X17": mu.reg_read(UC_ARM64_REG_X17),
                    "X18": mu.reg_read(UC_ARM64_REG_X18),
                    "X19": mu.reg_read(UC_ARM64_REG_X19),
                    "X20": mu.reg_read(UC_ARM64_REG_X20),
                    "X21": mu.reg_read(UC_ARM64_REG_X21),
                    "X22": mu.reg_read(UC_ARM64_REG_X22),
                    "X23": mu.reg_read(UC_ARM64_REG_X23),
                    "X24": mu.reg_read(UC_ARM64_REG_X24),
                    "X25": mu.reg_read(UC_ARM64_REG_X25),
                    "X26": mu.reg_read(UC_ARM64_REG_X26),
                    "X27": mu.reg_read(UC_ARM64_REG_X27),
                    "X28": mu.reg_read(UC_ARM64_REG_X28),
                    "X29": mu.reg_read(UC_ARM64_REG_X29)                }
                
                for reg_name, reg_value in regs.items():
                    print(f"{reg_name}: 0x{reg_value:x}")
                
                # 检查X0寄存器是否有返回值
                if regs["X0"] != 0:
                    print(f"注意: X0寄存器包含非零值，可能是函数返回值")
                    
                # 检查我们的数据缓冲区是否被修改
                try:
                    # 读取X0数据缓冲区的前16字节
                    x0_buffer_content = mu.mem_read(DATA_ADDR_1, 16)
                    print(f"\nX0缓冲区前16字节: {x0_buffer_content.hex()}")
                    
                    # 读取X1指向的数据缓冲区的前16字节
                    if regs["X1"] == POINTER_ADDR:
                        # 读取指针指向的地址
                        ptr_value = struct.unpack("<Q", mu.mem_read(POINTER_ADDR, 8))[0]
                        if ptr_value == DATA_ADDR_2:
                            X1_buffer_content = mu.mem_read(DATA_ADDR_2, 16)
                            print(f"X1缓冲区前16字节: {X1_buffer_content.hex()}")
                except:
                    print("无法读取数据缓冲区内容")
                    
            except:
                print("无法读取寄存器信息")
                
    except Exception as e:
        # 尝试获取执行位置信息（如果mu已初始化）
        if mu:
            try:
                current_pc = mu.reg_read(UC_ARM64_REG_PC)
                pc_info = f" [执行位置: 0x{current_pc:x}]"
            except:
                pc_info = " [无法获取执行位置]"
        else:
            pc_info = " [未初始化执行环境]"
        
        print(f"初始化或执行过程中出错: {e}{pc_info}")
        print("\n异常堆栈:")
        traceback.print_exc()
    finally:
        if mu:
            try:
                mu.emu_stop()
            except:
                pass

if __name__ == "__main__":
    print("使用Unicorn引擎模拟ARM64函数调用")
    emulate_libcore_function()