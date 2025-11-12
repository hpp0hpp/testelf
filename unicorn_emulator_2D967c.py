#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from unicorn import *
from unicorn.arm64_const import *
import struct
import os
import traceback
import json
# 引入capstone
import capstone
# from udbserver import udbserver

# 初始化capstone
cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
cs.detail = True  # 启用详细信息以获取操作数信息


# 添加UnicornSimpleHeap类实现
class UnicornSimpleHeap(object):
    """ 简单的堆实现，用于在模拟过程中处理malloc/free调用，并提供基本的保护页功能 """

    class HeapChunk(object):
        def __init__(self, actual_addr, total_size, data_size):
            self.total_size = total_size                        # 块的总大小（包括填充和保护页）
            self.actual_addr = actual_addr                      # 块的实际起始地址
            self.data_size = data_size                          # 用户请求的实际大小
            self.data_addr = actual_addr + 0x1000               # 数据实际开始的地址

        def is_buffer_in_chunk(self, addr, size):
            if addr >= self.data_addr and ((addr + size) <= (self.data_addr + self.data_size)):
                return True
            else:
                return False

    HEAP_MIN_ADDR = 0x00002000
    HEAP_MAX_ADDR = 0xFFFFFFFF

    _uc = None              # Unicorn引擎实例
    _chunks = []            # 已知块列表
    _debug_print = False    # 是否打印调试信息

    def __init__(self, uc, debug_print=False):
        self._uc = uc
        self._debug_print = debug_print
        # 添加内存访问钩子，用于实现保护页功能
        self._uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, self.__check_mem_access)

    def malloc(self, size):
        # 计算需要分配的总大小
        # 至少分配1个4K页，并在前后添加保护页
        total_chunk_size = 0x1000 + ((size + 0x1000 - 1) & ~(0x1000-1)) + 0x1000
        # 寻找可用的内存空间
        chunk = None
        for addr in range(self.HEAP_MIN_ADDR, self.HEAP_MAX_ADDR, 0x1000):
            try:
                self._uc.mem_map(addr, total_chunk_size, UC_PROT_READ | UC_PROT_WRITE)
                chunk = self.HeapChunk(addr, total_chunk_size, size)
                if self._debug_print:
                    log("分配 0x{:x}字节块 @ 0x{:016x}".format(chunk.data_size, chunk.data_addr))
                break
            except UcError as e:
                continue
        # 如果无法分配内存
        if chunk is None:
            return 0    
        self._chunks.append(chunk)
        return chunk.data_addr

    def calloc(self, size, count):
        # calloc只是malloc的简单封装
        return self.malloc(size * count)

    def realloc(self, ptr, new_size):
        # realloc实现：malloc(new_size) / memcpy(new, old, old_size) / free(old)
        if self._debug_print:
            log("重新分配块 @ 0x{:016x} 到 0x{:x}字节".format(ptr, new_size))
        old_chunk = None
        for chunk in self._chunks:
            if chunk.data_addr == ptr:
                old_chunk = chunk 
                break
        new_chunk_addr = self.malloc(new_size) 
        if old_chunk is not None and new_chunk_addr != 0:
            # 复制旧数据到新地址
            old_data = self._uc.mem_read(old_chunk.data_addr, min(old_chunk.data_size, new_size))
            self._uc.mem_write(new_chunk_addr, old_data)
            self.free(old_chunk.data_addr)
        return new_chunk_addr

    def free(self, addr):
        for chunk in self._chunks:
            if chunk.is_buffer_in_chunk(addr, 1):
                if self._debug_print:
                    log("释放 0x{:x}字节块 @ 0x{:016x}".format(chunk.data_size, chunk.data_addr))
                self._uc.mem_unmap(chunk.actual_addr, chunk.total_size)
                self._chunks.remove(chunk)
                return True
        return False

    def __check_mem_access(self, uc, access, address, size, value, user_data):
        for chunk in self._chunks:
            if address >= chunk.actual_addr and ((address + size) <= (chunk.actual_addr + chunk.total_size)):
                if not chunk.is_buffer_in_chunk(address, size):
                    if self._debug_print:
                        log("堆溢出/下溢尝试 {} 0x{:x}字节 @ {:016x}".format( 
                            "写入" if access == UC_MEM_WRITE else "读取", size, address))
                    # 强制内存访问错误
                    raise UcError(UC_ERR_READ_PROT)

# 定义内存映射的地址 - 使用更合适的地址空间
BASE_ADDR = 0xcbbcb000  # libcore.so的加载地址（避免使用0地址）
STACK_ADDR = 0x70000000  # 栈地址
STACK_SIZE = 0x100000  # 减小栈大小

# 用于记录跳转指令的字典
# 格式: {源地址偏移: [目标地址偏移列表]}
jump_records = {}

# 根据输入2.txt定义的指针链地址
DATA_ADDR_1 = 0x80000000  # 指针1地址 (x0)
DATA_ADDR_2 = 0x80001000  # 指针2地址
DATA_ADDR_3 = 0x80002000  # 指针3地址
X0_DATA_ADDR = 0x80003000  # x0指向的32字节数据

DATA_ADDR_4 = 0x81000000  # 指针4地址 (x1)
DATA_ADDR_5 = 0x81001000  # 指针5地址
X1_DATA_ADDR = 0x81002000  # x1指向的字符串

DATA_ADDR_6 = 0x82000000  # 指针6地址 (x2)
DATA_ADDR_7 = 0x82001000  # 指针7地址
X2_DATA_ADDR = 0x82002000  # x2指向的字符串

DATA_ADDR_8 = 0x83000000  # 指针8地址 (x4)
DATA_ADDR_9 = 0x83001000  # 指针9地址 (x3)
DATA_ADDR_10 = 0x83003000  # 指针10地址 (TPIDR_EL0)
X3_DATA_ADDR = 0x83002000  # x4指向的字符串
TPIDR_TARGET_ADDR = BASE_ADDR + 0x20d4fa688  # TPIDR_EL0指向的目标地址

OUT_DATA_ADDR = 0x84000000  # 输出的地址


# 根据输入2.txt中的数据定义
X0_HEX_DATA = "637C777BF26B6FC53001672BFED7AB76CA82C97DFA5947F0ADD4A2AF9CA472C0B7FD9326363FF7CC34A5E5F171D8311504C723C31896059A071280E2EB27B27509832C1A1B6E5AA0523BD6B329E32F8453D100ED20FCB15B6ACBBE394A4C58CFD0EFAAFB434D338545F9027F503C9FA851A3408F929D38F5BCB6DA2110FFF3D2CD0C13EC5F974417C4A77E3D645D197360814FDC222A908846EEB814DE5E0BDBE0323A0A4906245CC2D3AC629195E479E7C8376D8DD54EA96C56F4EA657AAE08BA78252E1CA6B4C6E8DD741F4BBD8B8A703EB5664803F60E613557B986C11D9EE1F8981169D98E949B1E87E9CE5528DF8CA1890DBFE6426841992D0FB054BB16"
# X1_STRING = "cBDw1t5m3WC9vH+9v7zBcHYHc75D1e0mbXuod2yPcqDZ1tImcWCpvtiTv2st+HeZbtzCvNyN32yDc8+937sh+85Cb8cw+/CMcH6NvHeHcI=="
X1_STRING = "0123456789"
X2_STRING = "ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv"
X3_STRING = "WonrnVkxeIxDcFbv"
TPIDR_HEX_DATA = "00000000000000003031323334353637383900ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00010203040506070809ffffffffffffff0a0b0c0d0e0fffffffffffffffffffffffffffffffffffffffffffffffffffff0a0b0c0d0e0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

# 转换hex字符串为字节数据
def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

# 将字符串转换为字节数据
def string_to_bytes(text):
    return text.encode('utf-8')

log_f =open("unicorn_emulator_2D967c_log.txt","w",encoding='utf-8')
def log(s):
    # log(s)
    log_f.write(s+"\n")
    log_f.flush()

# 读取libcore.so文件
def read_libcore_so(file_path):
    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except Exception as e:
        log(f"无法读取libcore.so文件: {e}")
        return None
def get_backtrace(uc, max_depth=10):
    backtrace = []
    # 读取当前帧指针FP（x29）
    fp = uc.reg_read(UC_ARM64_REG_X29)
    
    depth = 0
    while fp != 0 and depth < max_depth:
        try:
            # 读取FP指向的16字节（前8字节：prev_fp，后8字节：ret_addr）
            stack_data = uc.mem_read(fp, 16)
            prev_fp = struct.unpack('<Q', stack_data[:8])[0]  # 小端模式（ARM64默认）
            ret_addr = struct.unpack('<Q', stack_data[8:])[0]

            backtrace.append(ret_addr)


            
            fp = prev_fp  # 继续遍历上一层栈帧
            depth += 1
        except unicorn.UcError:
            # 内存访问失败（栈地址无效），终止遍历
            break
    return backtrace


def read_pointer_from_memory(mu, address):
    return struct.unpack('<Q', mu.mem_read(address, 8))[0]
# 初始化unicorn引擎并执行模拟
def emulate_libcore_function():
    mu = None
    heap = None
    try:
        # 创建Unicorn引擎实例 (ARM64)
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        
        # 读取libcore.so文件
        libcore_path = 'D:\\crack\\jiongciyuan\\unicorn\\libcore.bin'
        libcore_data = read_libcore_so(libcore_path)
        
        if not libcore_data:
            log("无法继续，缺少libcore.so文件")
            return

        try:
            # 确保内存块大小是4K对齐的
            lib_size = (len(libcore_data) + 0x10000 + 0xFFF) & ~0xFFF
            mu.mem_map(BASE_ADDR, lib_size, UC_PROT_ALL)

            mu.mem_map(STACK_ADDR, STACK_SIZE, UC_PROT_ALL)

            # 映射一个连续的大内存块来覆盖所有需要的地址
            mu.mem_map(0x80000000, 0x4000000, UC_PROT_ALL)  # 64MB连续内存

            mu.mem_map(OUT_DATA_ADDR & ~0xFFF  , 0x4000, UC_PROT_ALL)  # 
        except UcError as e:
            log(f"内存映射失败: {e} [初始化阶段]")
            return
        
        # 初始化堆模拟器
        log("初始化堆模拟器...")
        heap = UnicornSimpleHeap(mu, debug_print=False)
        
        # 加载libcore.so到内存
        mu.mem_write(BASE_ADDR, libcore_data)
        

        # 准备数据
        log("准备数据...")
        x0_data = hex_to_bytes(X0_HEX_DATA)
        x1_data = string_to_bytes(X1_STRING)
        x2_data = string_to_bytes(X2_STRING)
        x3_data = string_to_bytes(X3_STRING)

        
        # 额外的内存映射已经在上面完成，所有地址都在0x80000000-0x84000000范围内
        # 映射TPIDR_EL0指向的地址
        try:
            # 计算TPIDR_TARGET_ADDR所在的页
            tpidr_page = TPIDR_TARGET_ADDR & ~0xFFF
            mu.mem_map(tpidr_page, 0x1000, UC_PROT_ALL)
            log(f"映射TPIDR目标内存 @ 0x{tpidr_page:x}")
        except UcError as e:
            log(f"TPIDR目标内存映射失败: {e}")

        
        # 将数据写入内存
        log("将数据写入内存...")
        mu.mem_write(X0_DATA_ADDR, x0_data)
        mu.mem_write(X1_DATA_ADDR, x1_data)
        mu.mem_write(X2_DATA_ADDR, x2_data)
        mu.mem_write(X3_DATA_ADDR, x3_data)
        # 写入TPIDR_EL0指向的数据
        tpidr_data = hex_to_bytes(TPIDR_HEX_DATA)
        mu.mem_write(TPIDR_TARGET_ADDR, tpidr_data)
        # log(f"TPIDR数据写入完成，大小: {len(tpidr_data)} 字节")
        
        # 设置指针链
        log("设置指针链...")
        # 计算数据结尾地址
        x0_end_addr = X0_DATA_ADDR + len(x0_data)
        x1_end_addr = X1_DATA_ADDR + len(x1_data)
        x2_end_addr = X2_DATA_ADDR + len(x2_data)
        x3_end_addr = X3_DATA_ADDR + len(x3_data)
        
        # x0 链: 指针1 -> 指针2 -> 数据
        # 按照ARM64要求，在数据地址后面添加结尾地址
        mu.mem_write(DATA_ADDR_1, DATA_ADDR_2.to_bytes(8, byteorder='little'))
        mu.mem_write(DATA_ADDR_1+8, (DATA_ADDR_2+0x180).to_bytes(8, byteorder='little'))
        for i in range(16):
            mu.mem_write(DATA_ADDR_2+i*24, (X0_DATA_ADDR+i*16).to_bytes(8, byteorder='little'))
            mu.mem_write(DATA_ADDR_2+i*24+8, (X0_DATA_ADDR+(i+1)*16).to_bytes(8, byteorder='little'))
            mu.mem_write(DATA_ADDR_2+i*24+16, (X0_DATA_ADDR+(i+1)*16).to_bytes(8, byteorder='little'))
        # mu.mem_write(DATA_ADDR_2 + 8, x0_end_addr.to_bytes(8, byteorder='little'))  # 结尾地址
        mu.mem_write(BASE_ADDR+0x690ad8, DATA_ADDR_1.to_bytes(8, byteorder='little'))
        # # 写DATA_ADDR_1+60 一个地址
        mu.mem_write(DATA_ADDR_1 + 0x60, 0x80004000.to_bytes(8, byteorder='little'))
        mu.mem_write(DATA_ADDR_1 + 0x68, (0x80004000+0xf0).to_bytes(8, byteorder='little'))
        # mu.mem_write(0x80004000, 0x80005000.to_bytes(8, byteorder='little'))
        for i in range(10):
            mu.mem_write(0x80004000+i*24, (0x80005000+i*8).to_bytes(8, byteorder='little'))
            mu.mem_write(0x80004000+i*24+8, (0x80005000+(i+1)*8).to_bytes(8, byteorder='little'))
            mu.mem_write(0x80004000+i*24+16, (0x80005000+(i+1)*8).to_bytes(8, byteorder='little'))
        mu.mem_write(0x80005000, hex_to_bytes("010000000000000002000000000000000400000000000000080000000000000010000000000000002000000000000000400000000000000080000000000000001b000000000000003600000000000000"))
        #"01000000640072000200000064002e00040000006e0074000800000074002e00100000002e005600200000007300690040000000650064008000000063006b001b0000006500000036000000616e6472"

        # x1 链: 指针4 -> 字符串地址
        mu.mem_write(DATA_ADDR_4, X1_DATA_ADDR.to_bytes(8, byteorder='little'))
        mu.mem_write(DATA_ADDR_4 + 8, x1_end_addr.to_bytes(8, byteorder='little'))  # 结尾地址

        
        # x2 链: 指针6 -> 字符串地址
        mu.mem_write(DATA_ADDR_6, X2_DATA_ADDR.to_bytes(8, byteorder='little')) 
        mu.mem_write(DATA_ADDR_6 + 8, x2_end_addr.to_bytes(8, byteorder='little'))  # 结尾地址
        
        # x3: 指针8 -> 字符串地址
        mu.mem_write(DATA_ADDR_8, X3_DATA_ADDR.to_bytes(8, byteorder='little'))
        mu.mem_write(DATA_ADDR_8 + 8, x3_end_addr.to_bytes(8, byteorder='little'))  # 结尾地址
        
        # TPIDR_EL0的指针10 -> TPIDR_TARGET_ADDR
        mu.mem_write(DATA_ADDR_10, TPIDR_TARGET_ADDR.to_bytes(8, byteorder='little'))
        mu.mem_write(DATA_ADDR_10+0x28, hex_to_bytes('bab98ad68bd00d53'))
        
        # 设置寄存器
        log("设置寄存器...")
        mu.reg_write(UC_ARM64_REG_X0, DATA_ADDR_1)  # x0指向指针1
        mu.reg_write(UC_ARM64_REG_X1, DATA_ADDR_4)  # x1指向指针4
        mu.reg_write(UC_ARM64_REG_X2, DATA_ADDR_6)  # x2指向指针6
        mu.reg_write(UC_ARM64_REG_X3, DATA_ADDR_8)  # x3指向指针8
        mu.reg_write(UC_ARM64_REG_X4, X3_DATA_ADDR)  # x4指向字符串地址
        # 初始化x8寄存器
        # x8_value = BASE_ADDR + 0x15f338468
        mu.reg_write(UC_ARM64_REG_X8, OUT_DATA_ADDR)  # x8值为base_addr+0x15f338468
        
        # 初始化TPIDR_EL0寄存器
        mu.reg_write(UC_ARM64_REG_TPIDR_EL0, DATA_ADDR_10)  # TPIDR_EL0值为指针10
        log(f"TPIDR_EL0设置为: 0x{DATA_ADDR_10:x}，指向: 0x{TPIDR_TARGET_ADDR:x}")
        
        mu.reg_write(UC_ARM64_REG_SP, STACK_ADDR + STACK_SIZE - 16)  # 设置栈指针
        
        # 验证寄存器设置
        x0_val = mu.reg_read(UC_ARM64_REG_X0)
        X1_val = mu.reg_read(UC_ARM64_REG_X1)
        sp_val = mu.reg_read(UC_ARM64_REG_SP)

        
        # 模拟执行的函数地址 - 2d967c函数
        function_offset = 0x2d967c
        function_addr = BASE_ADDR + function_offset
        # 设置一个合理的函数结束地址（假设函数大小为0x1000字节）
        function_end_addr = BASE_ADDR + 0x2D9E2C
        
        # 设置一个简单的返回地址（函数执行完后跳到这里）
        return_addr = BASE_ADDR + 0x305F38 # 增加距离以避免冲突
        log(f"返回地址: 0x{return_addr:x}")
        
        # 在栈上压入返回地址
        log("在栈上压入返回地址...")
        mu.mem_write(STACK_ADDR + STACK_SIZE - 16, struct.pack("<Q", return_addr))
        
        # 添加内存访问钩子，但只在关键地址附近输出
        def hook_mem_access(uc, access, address, size, value, user_data):
            # 只监控关键地址范围的访问
            # if (BASE_ADDR - 0x1000 <= address <= BASE_ADDR + len(libcore_data) + 0x1000 or
            #     X0_DATA_ADDR - 0x100 <= address <= X0_DATA_ADDR + 0x1000 or
            #     X1_DATA_ADDR - 0x100 <= address <= X1_DATA_ADDR + 0x1000 or
            #     X2_DATA_ADDR - 0x100 <= address <= X2_DATA_ADDR + 0x1000 or
            #     X3_DATA_ADDR - 0x100 <= address <= X3_DATA_ADDR + 0x1000):
            offset = uc.reg_read(UC_ARM64_REG_PC) - BASE_ADDR
            # if offset not in [0x2D45E4,0x2D462C,0x2D4748,0x2D4770]: #0x2D45E4,0x2D462C,0x2D4748,0x2D4770
            #     return
            if access == UC_MEM_WRITE:
                try:
                    pass
                    # log(f"offset 0x{offset:x} write: 0x{value:x} at 0x{address:x}")
                except Exception as e:
                    pass

            elif access == UC_MEM_READ:
                #如果地址不是0x8开头的就忽略
                if  hex(address).startswith("0xcc"):
                    return
                try: 
                    value = int.from_bytes(mu.mem_read(address, size),byteorder='little') 
                    
                except Exception as e:
                    pass
        
        # 添加内存错误钩子 - 使用更简单的错误处理方式
        def hook_mem_error(uc, access, address, size, value, user_data):
            # 获取当前执行位置
            try:
                page_size = 0x1000
                page_start = address & ~(page_size - 1)  # 页对齐
                try:
                    uc.mem_map(page_start, page_size)  # 映射内存
                except unicorn.UcError:
                    pass  # 若已映射则忽略
                
                # 返回True表示“已处理异常”，模拟器继续执行
                # return True
                current_pc = uc.reg_read(UC_ARM64_REG_PC)
                # 继续执行
                offset = current_pc - BASE_ADDR
                pc_info = f" [执行位置: 0x{offset:x}],"
            except:
                pc_info = " [无法获取执行位置]"
            
            # 只输出重要的内存错误信息
            if address > 0x100000000:  # 过滤掉明显无效的地址
                # log(f"内存错误: 访问无效地址 0x{address:x}    {pc_info}")
                # 对于读取错误，我们可以尝试提供一个默认值
                if access == UC_MEM_READ_UNMAPPED:
                    log(f"内存错误: 读取无效地址 0x{address:x}    {pc_info}")

                    uc.mem_map(address & ~0xFFF, 0x1000)  # 映射一个页
                    uc.mem_write(address, value.to_bytes(size, 'little'))  # 写入默认值0
                    return True  # 继续执行，让Unicorn使用默认值
                elif access == UC_MEM_WRITE_UNMAPPED:
                    log(f"内存错误: 写入无效地址 0x{address:x} 值{value:x}   {pc_info}")
                    return_addr = mu.reg_read(UC_ARM64_REG_X30)
                    return_offset = return_addr - BASE_ADDR
                    log(f"返回地址: 0x{return_offset:x}")
                    # 收集backtrace的返回地址
                    ret_addrs = get_backtrace(uc)
                    # 计算偏移量
                    offsets = [hex(addr - BASE_ADDR) for addr in ret_addrs]
                    log("Backtrace offsets:", offsets)  # 输出各层调用的偏移地址
                    uc.mem_map(address & ~0xFFF, 0x1000)  # 映射一个页
                    return True  # 继续执行
            else:
                log(f"内存错误: 访问类型: {access}, 地址: 0x{address:x}, 大小: {size}{pc_info}")
                                #记录返回地址
                return_addr = mu.reg_read(UC_ARM64_REG_X30)
                return_offset = return_addr - BASE_ADDR
                log(f"返回地址: 0x{return_offset:x}")
                # 收集backtrace的返回地址
                ret_addrs = get_backtrace(uc)
                # 计算偏移量
                offsets = [hex(addr - BASE_ADDR) for addr in ret_addrs]
                log("Backtrace offsets:", offsets)  # 输出各层调用的偏移地址
            return True  # 对于其他错误，让它抛出异常以便我们可以捕获并处理

        # 定义地址钩子函数，用于在特定地址记录寄存器值和处理malloc调用
        def hook_code(uc, address, size, user_data):
            # global jump_records
            
            # 计算相对于BASE_ADDR的偏移量
            offset = address - BASE_ADDR
            # log(f"执行到偏移0x{offset:x}")
            if offset in [0x2D9D78,0x2D0278,0x2D024c,0x2D02a0]:
                r2 = mu.reg_read(UC_ARM64_REG_X2)
                print(mu.mem_read(read_pointer_from_memory(mu,r2), 112).hex())
                # 记录 x0和x21
                return
            if offset == 0x61A5C0:
                size = mu.reg_read(UC_ARM64_REG_X0)
                # 记录 x0和x21
                addr = heap.malloc(size)
                # 将分配的地址设置为返回值
                uc.reg_write(UC_ARM64_REG_X0, addr)

                # log(f"  malloc({size}) -> 0x{addr:x}")
                return_addr = mu.reg_read(UC_ARM64_REG_X30)
                # 执行跳转
                mu.reg_write(UC_ARM64_REG_PC, return_addr)
                return
            if offset == 0x61A5D0:
                # 记录 x0和x21
                addr = mu.reg_read(UC_ARM64_REG_X0)
                heap.free(addr)
                # log(f"  free(0x{addr:x})")
                return_addr = mu.reg_read(UC_ARM64_REG_X30)
                # 执行跳转
                mu.reg_write(UC_ARM64_REG_PC, return_addr)
            if offset == 0x619D60:
                # 模拟memmove
                dest = mu.reg_read(UC_ARM64_REG_X0)
                src = mu.reg_read(UC_ARM64_REG_X1)
                n = mu.reg_read(UC_ARM64_REG_X2)
                # 简单模拟：直接复制内存
                # 一次性读取并写入，避免逐字节操作的类型问题
                if n > 0:
                    data = mu.mem_read(src, n)
                    mu.mem_write(dest,bytes(data) )
                # log(f"  memmove(0x{dest:x}, 0x{src:x}, {n})")
                return_addr = mu.reg_read(UC_ARM64_REG_X30)
                # 执行跳转
                mu.reg_write(UC_ARM64_REG_PC, return_addr)
            if offset == 0x2DB108 or offset == 0x002d9738:

                dest = mu.reg_read(UC_ARM64_REG_X0)
                c = mu.reg_read(UC_ARM64_REG_W2)
                n = mu.reg_read(UC_ARM64_REG_X3)
                dest_sz = mu.reg_read(UC_ARM64_REG_X1)
                # 模拟 __memset_chk 函数
                for i in range(n):
                    mu.mem_write(dest + i, bytes([c]))
                # 返回值为 dest
                mu.reg_write(UC_ARM64_REG_X0, dest)
                # 执行函数返回
                # 获取返回地址
                return_addr = mu.reg_read(UC_ARM64_REG_X30)
                if offset == 0x002d9738:
                    return_addr =BASE_ADDR+ 0x002d973c
                # 执行跳转
                mu.reg_write(UC_ARM64_REG_PC, return_addr)
                # log("执行__memset_chk函数")
                return
        # 添加系统调用钩子，用于处理可能的系统调用形式的内存分配
        def hook_syscall(uc, user_data,size):
            # 获取X8寄存器中的系统调用编号
            syscall_num = uc.reg_read(UC_ARM64_REG_X8)
            
            # 系统调用编号64对应内存分配(malloc)
            if syscall_num == 64:
                size = uc.reg_read(UC_ARM64_REG_X0)
                if heap:
                    addr = heap.malloc(size)
                    # 将分配的地址设置为返回值
                    uc.reg_write(UC_ARM64_REG_X0, addr)
                    # log(f"系统调用: malloc({size}) -> 0x{addr:x}")
                return True
            
            # 系统调用编号65对应内存释放(free)
            elif syscall_num == 65:
                ptr = uc.reg_read(UC_ARM64_REG_X0)
                if heap:
                    result = heap.free(ptr)
                    log(f"系统调用: free(0x{ptr:x}) -> {'成功' if result else '失败'}")
                return True
            
            return False


        # 添加钩子
        log("添加调试钩子...")
        mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access)
        # mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_error)
        # 添加代码执行钩子
        # mu.hook_add(UC_HOOK_INTR, hook_syscall)

        # 添加系统调用钩子
        mu.hook_add(UC_HOOK_CODE, hook_code)
        
        
        try:
            # udbserver(mu, 1234, BASE_ADDR+0x2D05DC)
            # 简化执行策略，只执行有限数量的指令
            log("开始执行函数...")

            mu.emu_start(function_addr, function_end_addr)  
            log("函数执行完成")
            
            
            result_addr =read_pointer_from_memory (mu ,OUT_DATA_ADDR)
            result_addr1 = read_pointer_from_memory (mu ,OUT_DATA_ADDR+8)
            lenth = result_addr1 - result_addr
            result_data = mu.mem_read(result_addr, lenth)
            print(f"函数返回值 (x0): {result_data.hex()} 长度: {lenth} 字节, 地址: 0x{result_addr:x}")
            
            print("模拟执行完成")
            
        except UcError as e:
                # 尝试获取执行位置信息
                try:
                    current_pc = mu.reg_read(UC_ARM64_REG_PC)
                    offset = current_pc - BASE_ADDR
                    pc_info = f" [执行位置: 0x{offset:x}]"
                    #跳过当前位置继续执行
                    mu.reg_write(UC_ARM64_REG_PC, current_pc + 4)
                    # log(f"跳过当前位置继续执行{pc_info}")
                    

                except:
                    pc_info = " [无法获取执行位置]"
                
                log(f"模拟执行出错: {e}{pc_info}")
                

                
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
        
        log(f"初始化或执行过程中出错: {e}{pc_info}")
        log("\n异常堆栈:")
        traceback.print_exc()
    finally:
        if mu:
            try:
                mu.emu_stop()
            except:
                pass
    log_f.close()
if __name__ == "__main__":
    log("使用Unicorn引擎模拟ARM64函数调用")
    emulate_libcore_function()
