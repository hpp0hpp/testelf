# 算法3.c 转换为 Python - 优化版

# 删除numpy导入，因为简化后不再需要

# 简化hex_to_bytes函数，使用Python内置功能
def hex_to_bytes(hex_str):
    try:
        # Python内置函数可以直接处理十六进制字符串转换
        return bytearray.fromhex(hex_str)
    except ValueError:
        # 如果格式错误则返回None
        return None

# 简化simulate_neon_operations函数
def simulate_neon_operations(v15):
    a = v15 & 0xFF  # 直接取低8位，无需转换为字节数组
    not_a = (~a) & 0xFF
    const_7c = 0x7C

    # 简化后的位运算，使用中间变量提高可读性
    temp1 = (a & 0x8F) | (not_a & 0x70)
    v18_0 = ((temp1 ^ 0x70) & 0x21 | temp1 & 0xDE) ^ 0x3F | (~(temp1 ^ 0x70) & 0x90)
    
    temp2 = (a & 0x58) | (not_a & 0xA7)
    v18_8 = ((temp2 ^ 0x58) & 0x46 | temp2 & 0xB9) ^ 0x88 | (~(temp2 ^ 0x58) & 0x6F)

    # 计算并返回最终结果
    return (( (v18_8 & 0x83) | ((~v18_8 & 0xFF) & const_7c) ) ^ 
            v18_0 ^ const_7c | ((~v18_0 & 0xFF) & (~v18_8 & 0xFF))) & 0xFF

# 简化主函数
def sub_2D050C(s_box, data):
    """主要的算法函数 - RC4变种实现"""
    pos = 0
    counter = -53
    i = 0
    j = 0
    
    while pos < len(data):
        i = (i + 1) & 0xff
        res = i  # 保存当前i值
        
        # 计算j的新值
        j = (j + s_box[i]) & 0xff
        
        # 内联交换操作，删除swap_values函数调用
        s_box[res], s_box[j] = s_box[j], s_box[res]
        
        # 更新密钥流索引
        key_idx = (s_box[res] + s_box[j]) & 0xff
        
        # 获取当前待加密字节
        byte = data[pos] & 0xff
        pos_plus_52 = (pos + 52) & 0xff
        
        # 计算辅助变量
        v11 = (((pos_plus_52 & 1 | counter & 0x10) ^ 0x10 | 
                (pos_plus_52 & 0xE9 | counter & 0x16) ^ 7)) & 0xff
        v12 = (byte ^ 0xCC) & 0xff
        v13 = ((byte ^ 0xEE) & byte) & 0xff
        v14 = (counter | ~((counter & 0xEE | pos_plus_52 & 0x11) & 0xff)) & 0xff
        
        # 计算v8的值（左侧部分）
        part1 = (~byte & 0x40 | 0x10 | (v12 ^ 0xDD) & 6) & 0xff
        part2 = ((v12 ^ 0x8A) & (v12 ^ 0xDD) ^ 0xF9) & 0xff
        part5 = ((v12 ^ 0x8A) & (v12 ^ 0xDD) ^ 6) & 0xff
        part3 = (part1 ^ part2) & 0xff
        part6 = (part1 ^ part5) & 0xff
        part4 = (v13 ^ 0xB8) & 0xff
        part7 = (v13 | v12 ^ 0x22) & 0xff
        part8 = (((v12 ^ 0x22) & 0xEC | (v12 ^ 0xDD) & 0x12) ^ v13 ^ 0x12) & 0xff
        part9 = (part7 & ~part8) & 0xff
        
        left_side = (part3 & part4 | part6 & ~part4 | part9) & 0xff
        
        # 计算v8的值（右侧部分）
        part10 = (v14 & 2 ^ v14 & 0xFD ^ 0xFD) & 0xff
        part11 = (v11 ^ 2) & 0xff
        part12 = ~(v11 | v14) & 0xff
        part13 = (v14 & 2 ^ v14 & 0xFD ^ 2) & 0xff
        part14 = (v11 ^ 0xFD) & 0xff
        
        right_side = (part10 & part11 | part12 | part13 & part14) & 0xff
        v8 = (left_side ^ right_side) & 0xff
        
        # 获取密钥字节并应用NEON变换
        key_byte = s_box[key_idx] & 0xff
        transformed_key = simulate_neon_operations(key_byte)
        
        # 计算加密后的字节
        encrypted_byte = ((v8 ^ 0x90 | ~transformed_key) ^ 
                         (transformed_key | v8 ^ 0x6F)) & 0xff
        
        # 更新数据
        data[pos] = encrypted_byte
        pos += 1
        counter -= 1
    
    # 返回加密结果的十六进制表示
    return data.hex()

def main():
    rc4_sbox = "1491135391d8aad2d70a5b93ce59ac92cdb7d45b094309b1dd234278c926a5cf602df62d774912d688044a7cf07e734d999fdbdf8dc8579b07b05f6685a18703a11b4e25ab2058926d7b1f9d078c169aac386b5dc051770ff36b474fecf8f01fd9621b446402595fd2d58abb6a057ae0e5f23ec15252507e2e0671275ae0db36174f23dcdc21376af8a2827616689cc65dcbc8dfe6b6982fd86d8e90c6b51933449da56928fd6776e1b781b8488b12f3c198636e422cb873006e5c3c89c5198f80883a2a67efad93f90a7c40337ab35372e5e95720c2329caf7599bf1dbc97d3c41ee4f1308bfc38c5d02a94ea84568d0ed4c0e327daa8aac2a981542b0384e8a5d6b953addd5332c053f4cd74000000"
    a2_hex = "032a796e8d9063697c958af161b0b47cea89ec4c975dee68d3f3f1f340fb8dcd1a5fa1eb5bde414dc14398c6405de1f42ee4e393f470ddd321a4afa168d57aabab7f47977127d0608157620601bff19a2ec25e1eed83a4d19f93e2bc9129f3fb3f8cff0bd37832a0111450d59dfdcfb4"
    
    # 转换输入数据
    a1_bytes = hex_to_bytes(rc4_sbox)
    a2_bytes = hex_to_bytes(a2_hex)
    
    if a1_bytes is None or a2_bytes is None:
        print("hex 解码失败")
        return 1
    
    # 执行加密并打印结果
    result = sub_2D050C(a1_bytes, a2_bytes)
    print(result)
    return 0

if __name__ == "__main__":
    main()