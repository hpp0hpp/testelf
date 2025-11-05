# ARM64 逆向分析工具集

这是一个专业的ARM64二进制分析工具集，包含寄存器追踪和自动反混淆功能。

## 🎯 工具列表

### 1. 寄存器依赖追踪器 (`register_tracer.py`)

从一个汇编跳转指令（如 `BR X3`）向上递归追踪寄存器的赋值链，找出所有参与给该寄存器赋值的指令。

**特点**:
- ✅ 递归追踪寄存器依赖
- ✅ 处理MOV/MOVK立即数组装
- ✅ 生成依赖关系图
- ✅ 支持W/X寄存器自动映射

**使用**:
```bash
python register_tracer.py
```

### 2. ARM64反混淆工具 (`arm64_deobfuscator.py`)

全自动分析ARM64 SO文件，追踪间接跳转并转换为直接跳转，实现反混淆。

**特点**:
- 🚀 自动识别间接跳转 (BR/BLR)
- 🧠 使用Unicorn模拟器获取跳转目标
- 🔄 递归分析调用的函数（只追踪当前SO）
- 🗺️ 完整段映射（映射所有text/data/rodata段）
- 📚 多库支持（映射额外库提供数据段）
- 🎯 智能过滤（自动跳过外部库调用）
- 📝 生成详细分析报告
- 💉 自动Patch生成清理后的SO

**使用**:
```bash
python arm64_deobfuscator.py <SO文件> <偏移地址>

# 基本示例
python arm64_deobfuscator.py libnative.so 0x2DA014

# 映射额外的库（处理跨库引用）
python arm64_deobfuscator.py app.so 0x1000 --libs libc.so libm.so
```

## 📦 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
```

需要的库：
- `capstone` - ARM64反汇编
- `keystone-engine` - ARM64汇编
- `unicorn` - CPU模拟器
- `pyelftools` - ELF文件解析

### 示例1: 寄存器追踪

```bash
# 分析sample.txt中的BR X3指令
python register_tracer.py
```

输出：
- 找到16条相关指令
- 显示寄存器依赖关系
- 打印完整的指令列表

### 示例2: SO文件反混淆

```bash
# 反混淆SO文件
python arm64_deobfuscator.py app.so 0x1000

# 输出文件:
# - app_patched.so (Patch后的SO)
# - app_report.txt (详细报告)
```

## 📖 文档

- **[快速开始指南](quick_start.md)** - 5分钟快速上手
- **[反混淆工具详细文档](DEOBFUSCATOR_README.md)** - 完整功能说明和高级用法
- **[内存映射指南](MEMORY_MAPPING_GUIDE.md)** - ⭐ 新功能：完整段映射和多库支持
- **[输出示例说明](EXAMPLE_OUTPUT.md)** - ⭐ 查看实际运行输出和说明
- **[测试脚本](test_deobfuscator.py)** - 交互式测试和演示

## 🎓 典型应用场景

### 场景1: 分析控制流混淆

sample.txt展示了一个典型的间接跳转混淆：

```asm
第58行: BR X3              # 间接跳转
第42行: ADD X3, X1, X24    # X3由多个寄存器计算
第34行: LDR X1, [X9,X13]   # 依赖其他寄存器
...共16条相关指令
```

使用寄存器追踪器分析：
```bash
python register_tracer.py
```

### 场景2: 批量反混淆SO文件

```bash
# 1. 在IDA中找到混淆函数的偏移地址
# 2. 运行反混淆工具
python arm64_deobfuscator.py obfuscated.so 0x2DA014 --max-depth 5

# 3. 查看生成的报告
cat obfuscated_report.txt

# 4. 在IDA中加载patch后的文件进行进一步分析
ida64 obfuscated_patched.so
```

## 🔧 核心算法

### 寄存器追踪算法

1. **识别目标寄存器**: 从跳转指令提取寄存器（如 BR X3 → X3）
2. **向上扫描**: 在指令流中向上查找所有修改该寄存器的指令
3. **递归追踪**: 对每个源寄存器递归执行步骤1-2
4. **停止条件**: 遇到立即数赋值（MOV/ADRP等）或MOVK序列的起始MOV
5. **输出结果**: 按地址排序输出所有相关指令

### 反混淆算法

1. **反汇编函数**: 使用Capstone反汇编指定函数到RET指令
2. **识别间接跳转**: 找出所有BR/BLR指令
3. **追踪依赖**: 使用寄存器追踪算法找到所有相关指令
4. **模拟执行**: 用Unicorn模拟器执行相关指令，获取寄存器值
5. **生成Patch**: 用Keystone将间接跳转重新汇编为直接跳转
6. **递归分析**: 对BL/BLR调用的函数递归执行步骤1-5
7. **应用Patch**: 将新指令写入SO文件

## 📊 示例输出

### 寄存器追踪输出

```
涉及到的所有指令（共16条）:
================================================================================

 1. 第 16行: ADRP     X11, #off_6784C0@PAGE
 2. 第 17行: MOV      X12, #0xAE9E
 3. 第 19行: MOVK     X12, #0x2599,LSL#16
 ...
16. 第 42行: ADD      X3, X1, X24

寄存器依赖关系:
================================================================================
X3 ← {'X1', 'X24'} (第42行)
X1 ← {'X9', 'X13'} (第34行)
X9 ← {'X11'} (第24行)
...
```

### 反混淆输出

```
[*] 加载SO: libnative.so
[*] 文件大小: 1048576 字节
[*] 反汇编函数: 0x2da014
[!] 发现间接跳转: 0x2da0f4 - br x3
[*] 找到 16 条相关指令
[*] 模拟执行获取 x3 的值...
[+] x3 = 0x2da120
[+] Patch: 0x2da0f4: br x3 -> b #0x2da120
[+] 共生成 8 个patch
[+] Patch后的文件已保存: libnative_patched.so
```

## 🛠️ 高级选项

### 反混淆工具参数

```bash
python arm64_deobfuscator.py <SO文件> <偏移> [选项]

选项:
  --end END           指定函数结束地址
  -o, --output FILE   输出文件路径
  -r, --report FILE   报告文件路径
  --max-depth N       最大递归深度 (默认: 3)
```

### 完整参数

```bash
python arm64_deobfuscator.py <SO文件> <偏移> [选项]

选项:
  --libs, -l LIB1 LIB2 ...  额外的库文件（用于提供数据段）
  --end END                  函数结束地址
  -o, --output FILE          输出文件路径  
  -r, --report FILE          报告文件路径
  --max-depth N              最大递归深度 (默认: 3)
```

### 使用示例

```bash
# 指定函数范围
python arm64_deobfuscator.py lib.so 0x1000 --end 0x2000

# 映射额外库（当代码读取外部库数据时）
python arm64_deobfuscator.py app.so 0x1000 --libs libc.so libm.so

# 深度递归分析（只分析当前SO内的函数）
python arm64_deobfuscator.py lib.so 0x1000 --max-depth 5

# 完整命令
python arm64_deobfuscator.py app.so 0x2DA014 \
    --libs /system/lib64/libc.so \
    --max-depth 4 \
    -o patched.so \
    -r report.txt
```

## ⚠️ 注意事项

### 限制

1. **模拟器限制**: 某些系统调用或依赖外部数据的指令可能无法模拟
2. **跳转范围**: ARM64 B指令跳转范围为±128MB，超出范围无法patch
3. **递归深度**: 过深的递归会导致分析时间过长
4. **条件跳转**: 当前版本主要处理无条件间接跳转

### 建议

- ✅ 先用IDA分析代码结构
- ✅ 从单个函数开始测试
- ✅ 备份原始SO文件
- ✅ 验证patch后的代码逻辑

## 🤝 使用流程

### 完整工作流

```bash
# 1. 在IDA中找到混淆函数
# 记录偏移地址，例如 0x2DA014

# 2. 运行反混淆工具
python arm64_deobfuscator.py target.so 0x2DA014 --max-depth 4

# 3. 查看分析报告
cat target_report.txt

# 4. 加载patch后的SO到IDA
# File -> Open -> target_patched.so

# 5. 对比分析
# 使用BinDiff或手动对比原文件和新文件
```

## 📚 技术栈

- **Capstone**: ARM64反汇编引擎
- **Keystone**: ARM64汇编引擎
- **Unicorn**: 基于QEMU的CPU模拟器
- **pyelftools**: ELF文件格式解析

## 🎯 适用场景

- ✅ 控制流平坦化混淆分析
- ✅ 虚拟化保护分析
- ✅ 间接跳转目标定位
- ✅ 函数调用链追踪
- ✅ 二进制代码清理

## 📄 许可证

仅供学习和研究使用。

## 🔗 相关资源

- [ARM64指令集手册](https://developer.arm.com/documentation/)
- [Capstone官方文档](https://www.capstone-engine.org/)
- [Unicorn官方文档](https://www.unicorn-engine.org/)

## 🐛 故障排查

### 常见问题

**Q: 安装依赖失败？**
```bash
# 尝试逐个安装
pip install capstone
pip install keystone-engine
pip install unicorn
pip install pyelftools
```

**Q: 模拟执行失败？**
- 检查相关指令是否依赖外部数据
- 查看是否包含系统调用
- 尝试降低递归深度

**Q: 没有生成patch？**
- 查看报告中的目标地址是否为"未知"
- 检查跳转目标是否超出范围

更多帮助请查看 [DEOBFUSCATOR_README.md](DEOBFUSCATOR_README.md)

---

⭐ 如果这个工具对你有帮助，欢迎Star！
