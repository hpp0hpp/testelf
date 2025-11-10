def calculate_index(element_at_1):
    """实现给定的位运算算法，计算最终的索引值"""
    # 计算v11
    v11 = ((element_at_1 & 0x13) | 0x70000080) ^ (element_at_1 & 0xEC)
    
    # 计算v12
    v12 = ((v11 ^ 0x8FFFFF7F) & 0x1FFB6122) | (v11 & 0xDD)
    
    # 计算v13
    part1_v13 = ((v12 ^ 0x1FFB61A2) & 0x1DAA4105)
    part2_v13 = ((v11 ^ 0x8FFFFF7F) & (v11 ^ 0x8251227A) & 0xA25122FF)
    v13 = part1_v13 | part2_v13
    
    # 计算v14
    # 注意：(unsigned __int8)v12 在Python中可以通过v12 & 0xFF实现
    part1_v14 = (((v12 ^ 0x40009409) & 0x5921B58B) | (v12 & 0x6DA4074)) ^ 0x5FFBF5A4
    part2_v14 = ((v12 & 0xFF) ^ 2) & 0xF  # 模拟unsigned __int8的转换
    v14 = part1_v14 | part2_v14
    
    # 计算最终索引
    part1_index = v14 ^ 0xA6FBABF5
    part2_index = ((v13 ^ 0x5DAEDD0A) & 0x6FB8B25) | (v13 & 0xB90060DA)
    part3_index = v13 ^ 0x5DAEDD0A | v14
    index = (part1_index ^ part2_index) & part3_index
    
    return index

# 测试用例
if __name__ == "__main__":
    # 可以替换为实际的element_at_1值进行测试
    test_value = 0x55
    result = calculate_index(test_value)
    print(f"输入值: 0x{test_value:x}")
    print(f"计算结果: 0x{result:x}")