from binaryninja import *
from binaryninja.log import Logger
from .emulate import armDeJmpRegEmulate
import time
from unicorn.arm64_const import *

import capstone

cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
cs.detail = True  # 启用详细信息以获取操作数信息

logger = Logger(0, "dejmpreg_log")



#递归通过搜索变量的def_site来拿到所有涉及到的指令
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

    involve_insns = [] #涉及到的指令
    jmp_var = jmp_insn.dest.var
    var_stack = []
    var_stack.append(jmp_var)
    while len(var_stack) != 0: #拿到一次寄存器间接跳转混淆涉及到的所有指令
        cur_ssa_var = var_stack.pop()
        insn_ = cur_ssa_var.def_site #一条指令 应该是MediumLevelILSetVarSsa或MediumLevelILVarPhi
        if insn_ == None:
            break

        if isinstance(insn_, MediumLevelILVarPhi):  # 如果遇到phi了且不是2个或2个地址不一样, 则取最小的
            addr_list = []                          
            for v in insn_.src:
                addr_list.append(v.def_site.address)
            if (len(addr_list) != 2) or (len(set(addr_list)) != 1):
                min_index = addr_list.index(min(addr_list))
                insn_ = insn_.src[min_index].def_site
            # 或者直接就停止 
            """
            break
            """

        if insn_ in involve_insns:
            break #如果拿到的指令已经在之前获取到的指令中了, 说明遇到循环了
        else:
            involve_insns.append(insn_) #添加涉及到的指令

        if 'cond' in insn_.dest.name:#遇到cond:20#1 = x8#2 == 0x586b6221这种就不再继续了 要不然有可能遇到phi节点导致死循环
            break
            

        insn_right = insn_.src #这条指令=右边的表达式
        get_right_ssa_var(insn_right, var_stack) #拿到表达式中的变量             
    
    return involve_insns


def is_jmpob(insn_: InstructionTextToken):
    return (isinstance(insn_, MediumLevelILJump) or isinstance(insn_, MediumLevelILJumpTo))

def patch_directly(bv:BinaryView, address, value):

    logger.log_info(f"直接patch跳转地址 {hex(address)} -> {hex(value)}")
    binst = bv.get_disassembly(address).split(' ')[0]
    b_opcode = bv.arch.assemble(f"{binst[:-1]} {hex(value-address)}", address)
    state = bv.begin_undo_actions()
    bv.write(address, b_opcode)
    bv.commit_undo_actions(state)

# 这种混淆就是把跳转改为了jmp(var2)
# 其中var2 = mem[var1 (<< num)] + const 这些值其实都是可以确定的, 例如:
# if (Cond)
#   var1 = 0;
# else 
#   var1 = 1;
# var2 = data_1fd630[var1];
# var3 = var2 - 0x7218df2;
# jump(var3); 

# 反混淆的话, 我的思路是静态分析+模拟执行:
# 从mlil ssa层面, 可以获取到jump变量var的指令
# 然后层层向上找, 找到所有涉及到的指令,
# 然后拿到这些指令对应的汇编指令模拟执行.
def dejmpreg(bv: BinaryView, func: Function, jmp_insn: MediumLevelILJump|MediumLevelILCallSsa, emulator: armDeJmpRegEmulate, manual_value = None):
    if isinstance(jmp_insn, MediumLevelILCallSsa) and isinstance(jmp_insn.dest, MediumLevelILConstPtr):
        if jmp_insn.dest.constant>0:
            # patch_directly(bv, jmp_insn.address, jmp_insn.dest.constant)
            logger.log_warn(f'{jmp_insn.address:x} bl {jmp_insn.dest.constant:x}')
            return None, None
        else:
            jmp_sym_name = bv.get_symbol_at(jmp_insn.dest.constant).full_name
            if jmp_sym_name == None:
                logger.log_error(f"未找到符号名称: {hex(jmp_insn.dest.constant)}")

                return None, None
            else:
                logger.log_info(f"跳转到符号: {jmp_sym_name}")
                patch_content = f'{jmp_insn.address:x} bl {jmp_sym_name}'
                logger.log_warn(patch_content)
                return None, None

    mlil_ssa_func = func.mlil.ssa_form
    mlil_ssa_bb = jmp_insn.il_basic_block
    jmp_dest_var = jmp_insn.dest.var.var
    jmp_reg = bv.arch.get_reg_name(jmp_dest_var.storage)
    jmp_insn_addr = jmp_insn.address
    logger.log_info(f"开始分析 {hex(jmp_insn_addr)}...")

    #拿到涉及到的所有指令
    involve_insns = get_involve_insns(jmp_insn)
    logger.log_debug(f"involve_insns: {involve_insns}")
    involve_asm_addrs = get_involve_asms(involve_insns)



    #找到csel/cset/csinc指令以及指令地址
    condition_insn_names = ['csel', 'cset', 'csinc', 'cinc', 'csetm', 'csinv', 'csneg']
    condition_insn_addr = 0
    insn_token = None
    for addr in involve_asm_addrs:
        tmp_token = (bv.get_disassembly(addr)).split()
        if tmp_token[0] in condition_insn_names:
            insn_token = tmp_token
            condition_insn_addr = addr
            break
    if insn_token == None:
        start_addr = min(involve_asm_addrs)
        end_addr = jmp_insn_addr + bv.get_instruction_length(max(involve_asm_addrs))
        emulator.write_code_part(bv.read(start_addr, end_addr - start_addr), start_addr)
        opinfos = get_opinfos(bv, involve_asm_addrs)
        reg_value = emulator.run_specific_opcodes(opinfos, jmp_reg)
        logger.log_warn(f'{jmp_insn.address:x} bl {reg_value:x}')


        # logger.log_error(f"未找到{condition_insn_names}指令!")
        return None, None
    # 拿到csel/cset/csinc/cinc等指令设置的三个寄存器
    cond_set_value = []#true和false分支 要设置的值/寄存器
    cond_set_reg = insn_token[1][:-1] #去掉,
    if insn_token[0] == 'cset':
        cond_set_value = [1, 0]
    elif insn_token[0] == 'cinc':
        cond_set_value = [insn_token[2][:-1], insn_token[2][:-1]]
    elif insn_token[0] == 'csetm':
        cond_set_value = [-1, 0]
    else:
        cond_set_value = [insn_token[2][:-1], insn_token[3][:-1]]
    logger.log_debug(f"csx:{insn_token[0]} | csx addr: {hex(condition_insn_addr)} | csx value: {cond_set_value}")

    #拿到给csx的两个变量赋值的指令地址
    csx_var_addrs = []
    if (insn_token[0] != 'cset'):
        tmp_addrs = []
        for insn in involve_insns:
            if isinstance(insn, MediumLevelILVarPhi) and (len(insn.src) == 2):
                phi_var1 = insn.src[0].def_site
                phi_var2 = insn.src[1].def_site
                for llil in phi_var1.llils:
                    tmp_addrs.append(llil.address)
                for llil in phi_var2.llils:
                    tmp_addrs.append(llil.address)
                break
        for addr in tmp_addrs:
            token = (bv.get_disassembly(addr)).split()
            if (token[0] == 'mov') and (addr not in csx_var_addrs):
                csx_var_addrs.append(addr)
    # 如果csx赋值指令为空, 可能是cset, 也可能是某些原因(比如entry块复制)导致拿到的地址不全
    if (len(csx_var_addrs) == 0) and (insn_token[0] != 'cset'): 
        find_over = False
        pre_bb = mlil_ssa_bb.source_block #从前继块中搜索'mov x9, #..'这种指令, 找不到就只能手动分析了
        if (cond_set_value[0] == cond_set_value[1]) or ('xzr' in [cond_set_value[0], cond_set_value[1]]):
            search_count = 1 #如果两个寄存器相同, 或者有一个是xzr寄存器, 则只用搜索一个
        else:
            search_count = 2
        csx_value_reg = ['w' + cond_set_value[0][1:], 'w' + cond_set_value[1][1:]] 
        found_bbs = [pre_bb]
        while True:
            incomes = pre_bb.incoming_edges
            if (len(incomes) == 0):
                break #没有前继了
            if (len(incomes) == 1):
                pre_bb = pre_bb.incoming_edges[0].source
            else: #如果有多个income, 找地址最小的那一个
                min_bb = incomes[0].source
                for edge in incomes:
                    if (edge.source.start < min_bb.start):
                        min_bb = edge.source
                pre_bb = min_bb
            if pre_bb in found_bbs:
                logger.log_debug("已搜索过的块 可能遇到循环...")
                break
            else:
                found_bbs.append(pre_bb)
            
            cur_find_addr = pre_bb.end - pre_bb[-1][-1] #从后往前搜索
            while cur_find_addr >= pre_bb.start:
                insn_txt = bv.get_disassembly(cur_find_addr)
                token = insn_txt.split()
                if (token[0] == 'mov') and ((csx_value_reg[0] == token[1][:-1]) or (csx_value_reg[1] == token[1][:-1])):
                    csx_var_addrs.append(cur_find_addr)
                    logger.log_warn(f"使用可能的csx赋值指令 {hex(cur_find_addr)}: {insn_txt}")
                cur_find_addr -= bv.get_instruction_length(cur_find_addr)
                if len(csx_var_addrs) >= search_count:
                    find_over = True
                    break
            if find_over:
                break
        if find_over == False:
            logger.log_warn("未能自动搜索到csx赋值指令 分析可能出错...")
    if len(csx_var_addrs) > 2:
        logger.log_error(f"搜索到过多的csx赋值变量: {[hex(x) for x in csx_var_addrs]}")
        return None, None
    logger.log_debug(f"csx_var_addrs: {[hex(x) for x in csx_var_addrs]}")

    #补全涉及的指令
    for addr in csx_var_addrs:
        if addr not in involve_asm_addrs:
            involve_asm_addrs.append(addr)

    #把涉及到的指令的整个bb都写入
    involve_bbs = []
    for addr in involve_asm_addrs:
        bb = func.get_basic_block_at(addr)
        if bb not in involve_bbs:
            involve_bbs.append(bb)
    for bb in involve_bbs:
        bb_size = bb.end - bb.start
        opcodes =  bv.read(bb.start, bb_size)
        emulator.write_code_part(opcodes, bb.start)

    #找到本次混淆对应的cmp指令地址, cmp指令肯定在条件选择指令附近
    cmp_insn_addr = 0
    find_bb = func.get_basic_block_at(condition_insn_addr)
    find_addr = condition_insn_addr #先从当前bb找, 当前bb没有就往前继bb找
    while cmp_insn_addr == 0:
        find_token = (bv.get_disassembly(find_addr)).split()
        if find_token[0] == 'cmp':
            cmp_insn_addr = find_addr
            break

        if find_addr <= find_bb.start: #更新bb
            pre_edge = find_bb.incoming_edges
            if len(pre_edge) != 1:
                break #只能有一个前继
            find_bb = pre_edge[0].source
            find_addr = find_bb.end - find_bb[-1][-1] #[-1]是(token, size)
            continue

        op_len = bv.get_instruction_length(find_addr)
        find_addr -= op_len

    if cmp_insn_addr == 0:
        logger.log_error("未找到cmp指令!")
        return None, None
    else:
        verify_token = (bv.get_disassembly(cmp_insn_addr)).split()
        if verify_token[0] != 'cmp':
            logger.log_error(f"搜索到错误的cmp指令地址:{hex(cmp_insn_addr)}!")
            return  None, None
    logger.log_debug(f"cmp_insn_addr: {hex(cmp_insn_addr)}")

    #设置需要模拟执行的指令
    opinfos = get_opinfos(bv, involve_asm_addrs)

    #分别模拟执行不同的值获取对应的跳转地址
    jmp_values = []
    if manual_value != None:
        cond_set_value = manual_value #手动设置的值
    index = 0 
    for value in cond_set_value:
        mov_opcode = b''
        if manual_value != None:
            mov_opcode = bv.arch.assemble(f"mov {cond_set_reg}, {value}", condition_insn_addr)
        else:
            #如果是csinc指令, 不满足条件应该改为add x24, x1, #1 | csinc是条件不满足则xd=xm+1, cinc是条件满足则xd=xn+1
            if ((insn_token[0] == 'csinc' ) and (index == 1)) or ((insn_token[0] == 'cinc') and (index == 0)): 
                if value == 'xzr':#如果是xzr寄存器就不能用add, 相当于赋值为了1
                    mov_opcode = bv.arch.assemble(f"mov {cond_set_reg}, #1", condition_insn_addr) 
                else:
                    mov_opcode = bv.arch.assemble(f"add {cond_set_reg}, {value}, #1", condition_insn_addr) 
            elif (insn_token[0] == 'csinv') and (index == 1): 
                mov_opcode = bv.arch.assemble(f"mvn {cond_set_reg}, {value}", condition_insn_addr) #按位取反
            elif (insn_token[0] == 'sneg') and (index == 1):
                mov_opcode = bv.arch.assemble(f"neg {cond_set_reg}, {value}", condition_insn_addr) #取负值
            else:
                mov_opcode = bv.arch.assemble(f"mov {cond_set_reg}, {value}", condition_insn_addr) #汇编mov x4, x9
        #将csx reg指令改为mov reg指令
        cs_insn_len = bv.get_instruction_length(condition_insn_addr)
        emulator.change_select(condition_insn_addr, cs_insn_len, mov_opcode)
        reg_value = emulator.run_specific_opcodes(opinfos, jmp_reg)
        jmp_values.append(reg_value)
        index += 1
    logger.log_info(f"{insn_token[0]}->jmp_values: True:{hex(jmp_values[0])}, False:{hex(jmp_values[1])}")
    if jmp_values[0] == jmp_values[1]:
        logger.log_warn(f"本次分析{hex(jmp_insn_addr)}结果可能出错! 请检查涉及到的地址中是否遗漏了指令:{[hex(x) for x in involve_asm_addrs]}")
    #开始Patch!!
    addr_info = {'cmp':cmp_insn_addr, 'cond': condition_insn_addr, 'jmp': jmp_insn_addr, 'involves': involve_asm_addrs}
    # patch_addr_info = PatchSelect(bv, addr_info, jmp_values[0], jmp_values[1])
    csx_tokens = (bv.get_disassembly(condition_insn_addr)).split() #获取csel/cset/csinc等的token
    csx_cond = csx_tokens[-1] #条件eq/lt等
    jmp_tg= jmp_values[0]
    if jmp_values[0] -jmp_insn_addr==4:
        jmp_tg= jmp_values[1]
        csx_cond=  {'eq':'ne','ne':'eq','lt':'ge','ge':'lt','le':'gt','gt':'le','hs':'lo','lo':'hs','cc':'cs','cs':'cc'}.get(csx_cond,csx_cond)
        # logger.log_warn('修正跳转目标地址')
    
    bcc_cond = 'b.' + csx_cond
    bcc_txt = f"{jmp_insn_addr:x} {bcc_cond} {hex(jmp_tg)}"
    logger.log_warn(bcc_txt)
    need_nop_addrs = csx_var_addrs
    need_nop_addrs.append(cmp_insn_addr)
    return need_nop_addrs, None

def get_opinfos(bv, involve_asm_addrs):
    opinfos = []
    for addr in involve_asm_addrs:
        oplen = bv.get_instruction_length(addr)
        opinfos.append((addr, oplen))
    return opinfos

def get_involve_asms(involve_insns):
    involve_asm_addrs = [] #涉及到的汇编指令的地址 可能少csx赋值指令 后面补上
    for mlssa_insn in involve_insns:
        llil_insns = mlssa_insn.llils
        for insn_ in llil_insns:
            if insn_.address not in involve_asm_addrs:
                involve_asm_addrs.append(insn_.address)
    logger.log_debug(f"involve_asm_addrs: {[hex(x) for x in involve_asm_addrs]}")
    return involve_asm_addrs


def hook_code(uc, address, size, user_data):
    
    # 计算相对于BASE_ADDR的偏移量
    offset = address 

    # 获取指令
    instructions = list(cs.disasm(uc.mem_read(address, size), address))
    for i in instructions:
        print(f"  偏移0x{offset:x}: {i.mnemonic} {i.op_str}")
        # 记录X8,X9
        value_x8 = uc.reg_read(UC_ARM64_REG_X8)
        value_x9 = uc.reg_read(UC_ARM64_REG_X9)
        print(f"    X8: 0x{value_x8:x}, X9: 0x{value_x9:x}")
      
def dejmpreg_deep(bv: BinaryView, start_addr: int, end_addr: int=None):
    end_addr = end_addr if end_addr != None else start_addr

    logger.log_info(f"dejmpreg_deep from {hex(start_addr)} to {hex(end_addr)}")
    addr = start_addr
    find_bb=None
    find_inst=None
    adrp_insts=[]
    dejmpreg_emu = armDeJmpRegEmulate() #模拟执行器
    hex_bytes = bv.read(0x671f20, 0x1ca90)
    dejmpreg_emu.write_code_part(hex_bytes, 0x671f20)        
    
    dejmpreg_emu.add_code_hook(hook_code)
    while addr <= end_addr:
        dissam= bv .get_disassembly(addr).split(' ')
        if dissam[0] in ['br', 'blr']:
            target_mlil_ssa_func = None
            funcs  = sorted(bv.get_functions_containing(addr))
            func = funcs[0]
            for i in range(len(funcs)-1):
                if funcs[i].start <= addr and funcs[i+1].start > addr:
                    func = funcs[i]
                    break
            # if len(func) == 0:
            #     func =bv.create_user_function(addr)
            target_mlil_ssa_func = func.mlil.ssa_form
            find_bb = None
            for mlssa_bb in target_mlil_ssa_func:
                block_start_addr = mlssa_bb[0].address
                block_end_addr = mlssa_bb[-1].address
                if (addr >= block_start_addr) and (addr <= block_end_addr):
                    find_bb = mlssa_bb
                    break
            if (find_bb == None):
                logger.log_error(f"{hex(addr)}: 该地址处未找到对应的基本块!!!")
            find_insn = None
            if find_bb != None:
                for insn in find_bb:
                    if insn.address == addr:
                        find_insn = insn
                        break
            if (find_bb != None) and (find_insn != None):

                # dejmpreg_emu.set_reg("X26", 0x678000)
                # dejmpreg_emu.set_reg("X19", 0x678000)# todo： 加载所有的adrp
                dejmpreg_emu.set_reg("X22", 0xB73E9DAEFEA231C3)
                dejmpreg_emu.init_func_emu(func.start, 4 * 1024) #小于4k都是4k
                dejmpreg(bv, func, find_insn, dejmpreg_emu)
        if dissam[0] == 'adrp':
            dejmpreg_emu.set_reg(dissam[-2][:-1], int(dissam[-1], 16))
        addr += bv.get_instruction_length(addr)

