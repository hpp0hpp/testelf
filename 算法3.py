# 算法3.c 转换为 Python
import numpy as np

def hex_char_to_val(c):
    if c >= '0' and c <= '9':
        return ord(c) - ord('0')
    c = c.lower()
    if c >= 'a' and c <= 'f':
        return 10 + (ord(c) - ord('a'))
    return -1

def hex_to_bytes(hex_str):
    hex_len = len(hex_str)
    if hex_len % 2 != 0:
        return None
    out = bytearray(hex_len // 2)
    for i in range(0, hex_len, 2):
        hi = hex_char_to_val(hex_str[i])
        lo = hex_char_to_val(hex_str[i + 1])
        if hi < 0 or lo < 0:
            return None
        out[i // 2] = (hi << 4) | lo
    return out

def swap_values(a1, idx1, idx2):
    """模拟sub_2CFFC8函数的交换操作"""
    a1[idx1], a1[idx2] = a1[idx2], a1[idx1]
  
# def simulate_neon_operations(v15):
#     """模拟ARM NEON指令的操作（使用numpy优化版）"""
#     # 将16字节的常量值转换为numpy数组（uint8类型）
#     const1 = np.frombuffer(bytearray.fromhex('8f000000000000005800000000000000'), dtype=np.uint8)
#     const2 = np.frombuffer(bytearray.fromhex('701bf379d5273226a72410b7b572de8e'), dtype=np.uint8)
#     const3 = np.frombuffer(bytearray.fromhex('701bf379d527322658dbef484a8d2171'), dtype=np.uint8)
#     const4 = np.frombuffer(bytearray.fromhex('210000000000000046b97cf9fa22ad53'), dtype=np.uint8)
#     const5 = np.frombuffer(bytearray.fromhex('de10014000020200b900000000000000'), dtype=np.uint8)
#     const6 = np.frombuffer(bytearray.fromhex('3f0100022600200088205db7dc000f5b'), dtype=np.uint8)
#     const7 = np.frombuffer(bytearray.fromhex('90000000000000006f00000624228208'), dtype=np.uint8)
#     const8 = np.frombuffer(bytearray.fromhex('900458a0d88d10f76f00000624228208'), dtype=np.uint8)
#     const9 = np.frombuffer(bytearray.fromhex('ff1558e0fa8f30f7ffffffffffffffff'), dtype=np.uint8)
#     const10 = np.frombuffer(bytearray.fromhex('ff114142580232258399601758002901'), dtype=np.uint8)
    
#     # 模拟vdupq_n_s64(v15) - 小端序补零到8字节，然后重复到16字节
#     v15_le_bytes = v15.to_bytes(8, byteorder='little')
#     vdup_v15 = np.tile(np.frombuffer(v15_le_bytes, dtype=np.uint8), 2)
    
#     # 模拟vdupq_n_s64(~v15) - 更准确地模拟原始代码的有符号取反操作
#     # 先将v15转换为8字节小端序，然后对整个8字节取反
#     v15_le_bytes = v15.to_bytes(8, byteorder='little')
#     # 对每个字节进行按位取反
#     vnot_v15_le_bytes = bytes((~b) & 0xff for b in v15_le_bytes)
#     # 重复到16字节
#     vdup_not_v15 = np.tile(np.frombuffer(vnot_v15_le_bytes, dtype=np.uint8), 2)
    
#     # 模拟vandq_s8和vorrq_s8操作 - 向量化位运算
#     v16 = (vdup_v15 & const1) | (vdup_not_v15 & const2)
    
#     # 模拟veorq_s8操作 - 向量化异或
#     v17 = v16 ^ const3
    
#     # 模拟更复杂的组合操作 - 全部向量化
#     temp1 = v17 & const4
#     temp2 = v16 & const5
#     temp3 = temp1 | temp2
#     temp4 = temp3 ^ const6
#     temp5 = v17 & const7
#     temp6 = temp5 ^ const8
#     v18 = temp4 | temp6
    
#     # 继续模拟剩余的操作
#     v19 = v18 ^ const9
#     v20 = v18 & const10
    
#     # 获取特定位置的单个字节值（对应C代码中的vgetq_lane_u8函数）
#     lane20_8 = v20[8]
#     lane19_8 = v19[8]
#     lane20_0 = v20[0]
#     lane19_0 = v19[0]
#     const_7c = 0x7C
    
#     # 计算v21 - 与C代码中的位运算完全匹配
#     v21 = (lane20_8 | (lane19_8 & const_7c)) ^ lane20_0 ^ const_7c | (lane19_0 & lane19_8)
    
#     return v21 & 0xff  # 确保是8位无符号整数


def simulate_neon_operations(v15):
    a = v15.to_bytes(8, byteorder='little')[0]
    not_a = (~a) & 0xFF
    const_7c = 0x7C

    # 一次性计算v18_0和v18_8，完全合并中间步骤
    v18_0 = (((((a&0x8F)|(not_a&0x70))^0x70) & 0x21) | ((a&0x8F)|(not_a&0x70))&0xDE) ^ 0x3F | (~(((a&0x8F)|(not_a&0x70))^0x70) & 0x90)
    v18_8 = (((((a&0x58)|(not_a&0xA7))^0x58) & 0x46) | ((a&0x58)|(not_a&0xA7))&0xB9) ^ 0x88 | (~(((a&0x58)|(not_a&0xA7))^0x58) & 0x6F)

    return (( (v18_8&0x83) | ((~v18_8&0xFF) & const_7c) ) ^ v18_0 ^ const_7c | ((~v18_0&0xFF) & (~v18_8&0xFF))) & 0xFF
def sub_2D050C(a1, a2):
    """主要的算法函数"""
    v4 = 0
    v5 = -53
    v23 = 0
    v24 = 0
    
    while v4 < len(a2):
        v6 = (v23 + 1) & 0xff
        v7 = v6
        v23 = v6
        v24 = (v24 + a1[v6]) & 0xff  # 确保是8位无符号整数
        
        # 交换操作
        swap_values(a1, v7, v24)
        
        # 更新v7的值
        v7 = a1[v7] & 0xff
        v7 = (a1[v24] + v7) & 0xff
        
        v10 = a2[v4] & 0xff
        v11 = (((v4 + 52) & 1 | v5 & 0x10) ^ 0x10 | ((v4 + 52) & 0xE9 | v5 & 0x16) ^ 7) & 0xff
        v12 = (v10 ^ 0xCC) & 0xff
        v13 = ((v10 ^ 0xEE) & v10) & 0xff
        v14 = (v5 | ~((v5 & 0xEE | (v4 + 52) & 0x11) & 0xff)) & 0xff
        
        # 计算v8的值
        part1 = (~v10 & 0x40 | 0x10 | (v12 ^ 0xDD) & 6) & 0xff
        part2 = ((v12 ^ 0x8A) & (v12 ^ 0xDD) ^ 0xF9) & 0xff
        part3 = (part1 ^ part2) & 0xff
        part4 = (v13 ^ 0xB8) & 0xff
        part5 = ((v12 ^ 0x8A) & (v12 ^ 0xDD) ^ 6) & 0xff
        part6 = (part1 ^ part5) & 0xff
        part7 = (v13 | v12 ^ 0x22) & 0xff
        part8 = (((v12 ^ 0x22) & 0xEC | (v12 ^ 0xDD) & 0x12) ^ v13 ^ 0x12) & 0xff
        part9 = (part7 & ~part8) & 0xff
        
        left_side = (part3 & part4 | part6 & ~part4 | part9) & 0xff
        
        part10 = (v14 & 2 ^ v14 & 0xFD ^ 0xFD) & 0xff
        part11 = (v11 ^ 2) & 0xff
        part12 = ~(v11 | v14) & 0xff
        part13 = (v14 & 2 ^ v14 & 0xFD ^ 2) & 0xff
        part14 = (v11 ^ 0xFD) & 0xff
        
        right_side = (part10 & part11 | part12 | part13 & part14) & 0xff
        
        v8 = (left_side ^ right_side) & 0xff
        
        # 获取v15并模拟NEON操作
        v15 = a1[v7] & 0xff
        v21 = simulate_neon_operations(v15)
        
        # 更新v7的值
        v7 = ((v8 ^ 0x90 | ~v21) ^ (v21 | v8 ^ 0x6F)) & 0xff
        
        v5 -= 1
        if v4 < len(a2):
            a2[v4] = v7
        v4 += 1

    # 将a2转换为字符串并打印
    print(a2.hex())

def main():
    a1_hex = "1491135391d8aad2d70a5b93ce59ac92cdb7d45b094309b1dd234278c926a5cf602df62d774912d688044a7cf07e734d999fdbdf8dc8579b07b05f6685a18703a11b4e25ab2058926d7b1f9d078c169aac386b5dc051770ff36b474fecf8f01fd9621b446402595fd2d58abb6a057ae0e5f23ec15252507e2e0671275ae0db36174f23dcdc21376af8a2827616689cc65dcbc8dfe6b6982fd86d8e90c6b51933449da56928fd6776e1b781b8488b12f3c198636e422cb873006e5c3c89c5198f80883a2a67efad93f90a7c40337ab35372e5e95720c2329caf7599bf1dbc97d3c41ee4f1308bfc38c5d02a94ea84568d0ed4c0e327daa8aac2a981542b0384e8a5d6b953addd5332c053f4cd74000000"
    a2_hex = "032a796e8d9063697c958af161b0b47cea89ec4c975dee68d3f3f1f340fb8dcd1a5fa1eb5bde414dc14398c6405de1f42ee4e393f470ddd321a4afa168d57aabab7f47977127d0608157620601bff19a2ec25e1eed83a4d19f93e2bc9129f3fb3f8cff0bd37832a0111450d59dfdcfb4"
    
    a1_bytes = hex_to_bytes(a1_hex)
    a2_bytes = hex_to_bytes(a2_hex)
    
    if a1_bytes is None or a2_bytes is None:
        print("hex 解码失败")
        return 1
    

    
    sub_2D050C(a1_bytes, a2_bytes)
    return 0

if __name__ == "__main__":
    main()