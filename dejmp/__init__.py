from binaryninja import *
from binaryninja.log import Logger
import unicorn
from .emulate import armDeJmpRegEmulate
import capstone
from unicorn.arm64_const import *
import os
import json

cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
cs.detail = True  # 启用详细信息以获取操作数信息

logger = Logger(0, "simplified_dejmp_log")

# 递归通过搜索变量的def_site来拿到所有涉及到的指令
def get_involve_insns(jmp_insn: MediumLevelILJump):
    
    def get_right_ssa_var(expr, vars: list):
        if isinstance(expr, SSAVariable):
            vars.append(expr)
            return
        elif isinstance(expr, list):
            for ope in expr:
                if isinstance(ope, SSAVariable):
                    vars.append(ope)
            return

        if hasattr(expr, 'operands'):
            for ope in expr.operands:
                get_right_ssa_var(ope, vars)
        return

    involve_insns = []  # 涉及到的指令
    jmp_var = jmp_insn.dest.var
    var_stack = []
    var_stack.append(jmp_var)
    
    while var_stack:  # 拿到一次寄存器间接跳转混淆涉及到的所有指令
        cur_ssa_var = var_stack.pop()
        insn_ = cur_ssa_var.def_site 
        
        if insn_ is None:
            break

        # 处理phi节点
        if isinstance(insn_, MediumLevelILVarPhi):
            addr_list = []
            for v in insn_.src:
                addr_list.append(v.def_site.address)
            if (len(addr_list) != 2) or (len(set(addr_list)) != 1):
                min_index = addr_list.index(min(addr_list))
                insn_ = insn_.src[min_index].def_site

        if insn_ in involve_insns:
            break  # 避免循环
        
        involve_insns.append(insn_)

        # 避免遇到phi节点导致死循环
        if hasattr(insn_.dest, 'name') and 'cond' in insn_.dest.name:
            break
            
        insn_right = insn_.src  # 这条指令=右边的表达式
        get_right_ssa_var(insn_right, var_stack)  # 拿到表达式中的变量             
    
    return involve_insns

# 获取涉及的汇编指令地址
def get_involve_asms(involve_insns):
    if not isinstance(involve_insns, list):
        involve_insns=[involve_insns]
    involve_asm_addrs = []
    for mlssa_insn in involve_insns:
        llil_insns = mlssa_insn.llils
        for insn_ in llil_insns:
            if insn_.address not in involve_asm_addrs:
                involve_asm_addrs.append(insn_.address)
    logger.log_debug(f"涉及的汇编地址: {[hex(x) for x in involve_asm_addrs]}")
    return involve_asm_addrs

# 获取指令信息
def get_opinfos(bv:BinaryView, involve_asm_addrs):
    opinfos = []
    for addr in involve_asm_addrs:
        oplen = bv.get_instruction_length(addr)
        opinfos.append((addr, oplen))
    return opinfos

def get_condition_insn(bv:BinaryView,involve_asm_addrs):
    condition_insn_names = ['csel', 'cset', 'csinc', 'cinc', 'csetm', 'csinv', 'csneg']

    isntrus=[]
    for addr in involve_asm_addrs:
        insn_text = bv.get_disassembly(addr)
        tokens = insn_text.split()
        if tokens and tokens[0] in condition_insn_names:
            condition_insn = tokens
            condition_insn_addr = addr
            isntrus.append((condition_insn_addr, condition_insn))
    return isntrus

def get_cond_opcodes(bv:BinaryView,condition_insn_addr,condition_insn):
    cond_reg = condition_insn[1][:-1]  # 去掉逗号
    cond_name = condition_insn[0]
        
    # 确定条件选择指令的两个可能值
    if cond_name == 'cset':
        cond_values = [1, 0]  # true和false分支的值
    elif cond_name == 'cinc':
        cond_values = [condition_insn[2][:-1], condition_insn[2][:-1]]
    elif cond_name == 'csetm':
        cond_values = [-1, 0]
    else:
        cond_values = [condition_insn[2][:-1], condition_insn[3][:-1]]
    
    logger.log_debug(f"条件指令: {cond_name} 地址: {hex(condition_insn_addr)} 值: {cond_values}")
    
    condition_data = {
        'addr': condition_insn_addr,
    }
    csx_tokens = (bv.get_disassembly(condition_insn_addr)).split() #获取csel/cset/csinc等的token
    csx_cond = csx_tokens[-1] #条件eq/lt等
    condition_data['csx_cond']=csx_cond

    # bcc_cond = 'b.' + csx_cond
    # 分别模拟两种条件状态
    for i, value in enumerate(cond_values):
        # 根据不同指令类型生成不同的替换指令
        if cond_name == 'csinc' and i == 1:  # 条件不满足时 xd = xm + 1
            if value == 'xzr':
                mov_opcode = bv.arch.assemble(f"mov {cond_reg}, #1", condition_insn_addr)
            else:
                mov_opcode = bv.arch.assemble(f"add {cond_reg}, {value}, #1", condition_insn_addr)
        elif cond_name == 'cinc' and i == 0:  # 条件满足时 xd = xn + 1
            if value == 'xzr':
                mov_opcode = bv.arch.assemble(f"mov {cond_reg}, #1", condition_insn_addr)
            else:
                mov_opcode = bv.arch.assemble(f"add {cond_reg}, {value}, #1", condition_insn_addr)
        elif cond_name == 'csinv' and i == 1:  # 条件不满足时取反
            mov_opcode = bv.arch.assemble(f"mvn {cond_reg}, {value}", condition_insn_addr)
        elif cond_name == 'csneg' and i == 1:  # 条件不满足时取负
            mov_opcode = bv.arch.assemble(f"neg {cond_reg}, {value}", condition_insn_addr)
        else:
            mov_opcode = bv.arch.assemble(f"mov {cond_reg}, {value}", condition_insn_addr)
        
        condition_data[f'value{i}'] = mov_opcode

    return condition_data

jmps = {}

def hook_code(uc, address, size, user_data):
    # 获取指令
    instructions = list(cs.disasm(uc.mem_read(address, size), address))
    # print(f'执行到地址: {hex(address)} 指令: {[i.mnemonic + " " + i.op_str for i in instructions]}')
    x8_val = uc.reg_read(UC_ARM64_REG_X8)
    x9_val = uc.reg_read(UC_ARM64_REG_X9)
    # print(f"x8: {hex(x8_val)} x9: {hex(x9_val)} ")
    i=instructions[0]
    #记录branch指令的目的地
    if i.mnemonic in ['br', 'blr']:
        reg=getattr(unicorn.arm64_const, f"UC_ARM64_REG_{ i.op_str.upper()}")
        tg_address = uc.reg_read(reg)
        logger.log_warn(f"{address:x} {i.mnemonic[:-1]} {tg_address:x}")
        # 将跳转记录到全局 jmps（源地址 -> 目的地址集合）
        try:
            global jmps
            if address not in jmps:
                jmps[address] = {'targets': [], 'type': i.mnemonic}  # 记录跳转类型（br或blr）

            if int(tg_address)<0xffffffff and int(tg_address) not in jmps[address]['targets']:
                jmps[address]['targets'].append(int(tg_address))
        except Exception as e:
            logger.log_error(f"记录 jmps 出错: {e}")
        uc.reg_write(UC_ARM64_REG_PC, address + size)  # 设置PC到下一条指令，防止死循环
    # if address == 0x2d97a4:
    #     # 记录x8，x9,x22,x26,x19,x25寄存器的值
    #     x8_val = uc.reg_read(UC_ARM64_REG_X8)
    #     x9_val = uc.reg_read(UC_ARM64_REG_X9)
    #     x22_val = uc.reg_read(UC_ARM64_REG_X22)
    #     x26_val = uc.reg_read(UC_ARM64_REG_X26)
    #     x19_val = uc.reg_read(UC_ARM64_REG_X19)
    #     x25_val = uc.reg_read(UC_ARM64_REG_X25)
    #     print(f"x8: {hex(x8_val)} x9: {hex(x9_val)} x22: {hex(x22_val)} x26: {hex(x26_val)} x19: {hex(x19_val)} x25: {hex(x25_val)}")
# 简化版的深度反混淆函数
def dejmp(bv: BinaryView, start_addr: int, end_addr: int = None):
    end_addr = end_addr if end_addr is not None else start_addr
    logger.log_info(f"开始简化版反混淆: 从 {hex(start_addr)} 到 {hex(end_addr)}")
    # 清空全局 jmps，以便本次运行收集新的跳转记录
    global jmps
    try:
        jmps.clear()
    except Exception:
        jmps = {}
    
    # 初始化模拟器
    emulator = armDeJmpRegEmulate()
    emulator.init_func_emu(start_addr, 4 * 1024)  # 4KB的代码空间
    code_bytes = bv.read(start_addr, 4 * 1024)
    emulator.write_code_part(code_bytes, start_addr)
    emulator.add_code_hook(hook_code)

    # 加载跳转表段（根据原始代码中的硬编码地址）
    code_start = 0x671f20
    code_size = 0x1ca90
    hex_bytes = bv.read(code_start, code_size)
    emulator.write_code_part(hex_bytes, code_start)

    # 重新遍历，分析间接跳转指令
    addr = start_addr
    results = []
    involve_asm_addrs = []
    branch_addrs = []
    while addr <= end_addr:
        disasm = bv.get_disassembly(addr).split()
        # 找到包含该地址的函数
        funcs = sorted(bv.get_functions_containing(addr))
        if not funcs:
            logger.log_warn(f"未找到包含地址 {hex(addr)} 的函数")
            funcs = [bv.create_user_function(addr)]
            # addr += bv.get_instruction_length(addr)
            # continue
                
        # 检查是否是间接跳转指令
        if disasm and disasm[0] in ['br', 'blr']:
            branch_addrs.append(addr)

            # 确定正确的函数
            func = funcs[0]
            for i in range(len(funcs) - 1):
                if funcs[i].start <= addr and funcs[i + 1].start > addr:
                    func = funcs[i]
                    break
            
            # 获取MLIL SSA形式
            mlil_ssa_func = func.mlil.ssa_form
            
            # 找到对应的基本块和指令
            find_bb = None
            for mlssa_bb in mlil_ssa_func:
                if mlssa_bb[0].address <= addr <= mlssa_bb[-1].address:
                    find_bb = mlssa_bb
                    break
            
            if not find_bb:
                logger.log_warn(f"未找到包含地址 {hex(addr)} 的基本块")
                addr += bv.get_instruction_length(addr)
                continue
            find_insn = None
            for insn in find_bb:
                if insn.address == addr:
                    find_insn = insn
                    break
            jmp_insn = find_insn
            if isinstance(jmp_insn, MediumLevelILCallSsa) and isinstance(jmp_insn.dest, MediumLevelILConstPtr):
                if jmp_insn.dest.constant>0:
                    # patch_directly(bv, jmp_insn.address, jmp_insn.dest.constant)
                    logger.log_warn(f'{jmp_insn.address:x} {disasm[0]} {jmp_insn.dest.constant:x}')
                    try:
                        address = jmp_insn.address
                        tg_address = jmp_insn.dest.constant
                        if address not in jmps:
                            jmps[address] = {'targets': [], 'type': disasm[0]}  # 直接跳转用bl

                        if int(tg_address) not in jmps[address]['targets']:
                            jmps[address]['targets'].append(int(tg_address))
                    except Exception as e:
                        logger.log_error(f"记录 jmps 出错: {e}")
                else:
                    jmp_sym_name = bv.get_symbol_at(jmp_insn.dest.constant).full_name
                    if jmp_sym_name == None:
                        logger.log_error(f"未找到符号名称: {hex(jmp_insn.dest.constant)}")

                    else:
                        logger.log_info(f"跳转到符号: {jmp_sym_name}")
                        patch_content = f'{jmp_insn.address:x} {disasm[0]} {jmp_sym_name}'
                        try:
                            address = jmp_insn.address
                            if address not in jmps:
                                jmps[address] = {'targets': [], 'type': disasm[0]}  # 符号跳转用bl

                            if jmp_sym_name not in jmps[address]['targets']:
                                jmps[address]['targets'].append(jmp_sym_name)
                        except Exception as e:
                            logger.log_error(f"记录 jmps 出错: {e}")
                        logger.log_warn(patch_content)
                involve_asm_addrs +=get_involve_asms(find_insn)
            else:
                involve_insns = get_involve_insns(find_insn)
                involve_asm_addrs +=get_involve_asms(involve_insns)
                involve_asm_addrs.append(jmp_insn.address)

        # 移动到下一条指令
        addr += bv.get_instruction_length(addr)

    involve_asm_addrs = sorted(list(set(involve_asm_addrs)))
    opinfos = get_opinfos(bv, sorted(involve_asm_addrs))
    
    # 切换条件指令并运行
    condition_instrs= get_condition_insn(bv, involve_asm_addrs)
    condition_instrs_data = []
    for condition_insns in condition_instrs:
        condition_instrs_data.append(get_cond_opcodes(bv, condition_insns[0], condition_insns[1]))
    for value in ['value0', 'value1']:
        for condition_instr in condition_instrs_data:
                emulator.change_select(condition_instr['addr'], bv.get_instruction_length(condition_instr['addr']),condition_instr [value])
        emulator.run_specific_opcodes(opinfos, 'x0')
    # 模拟执行完成后，处理 jmps 并保存到文件
    # 便于查找最近的前置条件指令：按地址排序
    sorted_conditions = sorted(condition_instrs_data, key=lambda x: x.get('addr', 0)) if condition_instrs_data else []
    # 处理每个跳转记录：如果有多个目标，添加条件信息
    for addr in jmps:
        if len(jmps[addr]['targets']) >= 2 and sorted_conditions:
            prev_cond = None
            for cond in sorted_conditions:
                if cond.get('addr', 0) < addr:
                    prev_cond = cond
                else:
                    break
            if prev_cond:
                jmps[addr]['csx_cond'] = prev_cond.get('csx_cond')

    # 保存到插件目录下的 jmps.txt（覆盖写入），以 JSON 格式保存
    try:
        base_dir = os.path.dirname(__file__)
        jmps_file = os.path.join(base_dir, 'jmps.txt')
        with open(jmps_file, 'w', encoding='utf-8') as f:
            json.dump(jmps, f, indent=2, ensure_ascii=False)
        logger.log_info(f"已将 jmps 结果保存到 {jmps_file}")
    except Exception as e:
        logger.log_error(f"写入 jmps 文件失败: {e}")

    logger.log_info(f"反混淆完成，共处理 {len(results)} 个间接跳转")
    return results

# # 插件命令注册
# def register_plugin_commands():
#     PluginCommand.register_for_address_range(
#         "简化版DeJmpReg", 
#         "分析并记录指定地址范围内的寄存器间接跳转目标",
#         dejmp
#     )

# # 当插件加载时注册命令
# register_plugin_commands()