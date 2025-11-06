#!/usr/bin/env python3
"""
Unicorn Hook Script for AES Algorithm Analysis
Monitor and record all critical encryption operations
"""

from unicorn import *
from unicorn.arm64_const import *
import struct
import json
from collections import defaultdict

class AESHookCollector:
    """Collect and analyze AES encryption data"""
    
    def __init__(self):
        self.call_count = defaultdict(int)
        self.captured_data = {
            'main_function': [],
            'key_derivation': [],
            'state_buffer_snapshots': [],
            'key_expansion_rounds': [],
            'sbox_lookups': [],
            'round_keys': [],
            'rc4_states': []
        }
        self.current_context = {}
        
    def save_to_file(self, filename='unicorn_capture.json'):
        """Save all captured data to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.captured_data, f, indent=2)
        print(f"[+] Saved captured data to {filename}")

# Global collector instance
collector = AESHookCollector()

# ============================================
# Utility Functions
# ============================================

def read_string(uc, addr, max_len=256):
    """Read null-terminated string from memory"""
    try:
        data = uc.mem_read(addr, max_len)
        end = data.find(b'\x00')
        if end != -1:
            return data[:end]
        return data
    except:
        return b''

def read_vector_info(uc, vector_addr):
    """Read std::vector structure (begin, end, capacity)"""
    try:
        begin = struct.unpack('<Q', uc.mem_read(vector_addr, 8))[0]
        end = struct.unpack('<Q', uc.mem_read(vector_addr + 8, 8))[0]
        length = end - begin
        return {'begin': begin, 'end': end, 'length': length}
    except:
        return None

def dump_memory(uc, addr, size, label="Memory"):
    """Dump memory content in hex"""
    try:
        data = uc.mem_read(addr, size)
        hex_str = data.hex()
        print(f"[{label}] @0x{addr:x} ({size} bytes): {hex_str[:128]}{'...' if len(hex_str) > 128 else ''}")
        return data
    except Exception as e:
        print(f"[{label}] Failed to read @0x{addr:x}: {e}")
        return None

def dump_registers(uc, label="Registers"):
    """Dump ARM64 registers"""
    print(f"\n[{label}]")
    print(f"  X0  = 0x{uc.reg_read(UC_ARM64_REG_X0):016x}")
    print(f"  X1  = 0x{uc.reg_read(UC_ARM64_REG_X1):016x}")
    print(f"  X2  = 0x{uc.reg_read(UC_ARM64_REG_X2):016x}")
    print(f"  X3  = 0x{uc.reg_read(UC_ARM64_REG_X3):016x}")
    print(f"  X8  = 0x{uc.reg_read(UC_ARM64_REG_X8):016x}")
    print(f"  SP  = 0x{uc.reg_read(UC_ARM64_REG_SP):016x}")
    print(f"  PC  = 0x{uc.reg_read(UC_ARM64_REG_PC):016x}")

# ============================================
# Hook: Main Encryption Function (0x2D967C)
# ============================================

def hook_main_entry(uc, address, size, user_data):
    """Hook at main encryption function entry"""
    print("\n" + "="*60)
    print("[MAIN] AES Encryption Function Called")
    print("="*60)
    
    # Read parameters
    cipher_handle = uc.reg_read(UC_ARM64_REG_X0)
    plaintext_ptr = uc.reg_read(UC_ARM64_REG_X1)
    key_ptr = uc.reg_read(UC_ARM64_REG_X2)
    iv_ptr = uc.reg_read(UC_ARM64_REG_X3)
    output_ptr = uc.reg_read(UC_ARM64_REG_X8)
    
    print(f"[MAIN] cipher_handle = 0x{cipher_handle:x}")
    print(f"[MAIN] plaintext     = 0x{plaintext_ptr:x}")
    print(f"[MAIN] key           = 0x{key_ptr:x}")
    print(f"[MAIN] iv            = 0x{iv_ptr:x}")
    print(f"[MAIN] output        = 0x{output_ptr:x}")
    
    # Read plaintext
    pt_info = read_vector_info(uc, plaintext_ptr)
    if pt_info and pt_info['length'] > 0:
        plaintext_data = dump_memory(uc, pt_info['begin'], 
                                      min(pt_info['length'], 256), 
                                      "PLAINTEXT")
    
    # Read key
    key_info = read_vector_info(uc, key_ptr)
    if key_info and key_info['length'] > 0:
        key_data = dump_memory(uc, key_info['begin'], 
                               min(key_info['length'], 64), 
                               "KEY")
    
    # Read IV
    iv_info = read_vector_info(uc, iv_ptr)
    if iv_info and iv_info['length'] > 0:
        iv_data = dump_memory(uc, iv_info['begin'], 
                              min(iv_info['length'], 32), 
                              "IV")
    
    # Store context
    collector.current_context = {
        'cipher_handle': cipher_handle,
        'plaintext_ptr': plaintext_ptr,
        'key_ptr': key_ptr,
        'iv_ptr': iv_ptr,
        'output_ptr': output_ptr
    }
    
    collector.call_count['main'] += 1

def hook_main_exit(uc, address, size, user_data):
    """Hook at main function exit"""
    print("\n[MAIN] Encryption Completed")
    
    # Read output
    if 'output_ptr' in collector.current_context:
        output_ptr = collector.current_context['output_ptr']
        output_info = read_vector_info(uc, output_ptr)
        if output_info and output_info['length'] > 0:
            dump_memory(uc, output_info['begin'], 
                       min(output_info['length'], 256), 
                       "CIPHERTEXT")
    
    print("="*60 + "\n")

# ============================================
# Hook: Key Derivation (0x2DA014)
# ============================================

def hook_key_derivation_entry(uc, address, size, user_data):
    """Hook key derivation function"""
    print("\n[KEY_DERIV] === Key Derivation Started ===")
    
    password_ptr = uc.reg_read(UC_ARM64_REG_X0)
    output_ptr = uc.reg_read(UC_ARM64_REG_X1)
    
    pwd_info = read_vector_info(uc, password_ptr)
    if pwd_info and pwd_info['length'] > 0:
        dump_memory(uc, pwd_info['begin'], 
                   min(pwd_info['length'], 64), 
                   "KEY_DERIV_INPUT")
    
    collector.call_count['key_derivation'] += 1

def hook_key_derivation_seed(uc, address, size, user_data):
    """Hook PRNG seed initialization (0x2DA064)"""
    seed_value = uc.reg_read(UC_ARM64_REG_W8)
    print(f"[SEED] Initial seed = 0x{seed_value:08x} (DEADBEEF expected)")
    
    collector.captured_data['key_derivation'].append({
        'type': 'seed_init',
        'value': seed_value
    })

def hook_key_derivation_round(uc, address, size, user_data):
    """Hook each derivation round (0x2DA248)"""
    v47 = uc.reg_read(UC_ARM64_REG_W8)
    round_num = collector.call_count['derivation_round']
    
    print(f"[SEED] Round {round_num}: seed = 0x{v47:08x}")
    
    collector.captured_data['key_derivation'].append({
        'type': 'round',
        'round': round_num,
        'seed': v47
    })
    
    collector.call_count['derivation_round'] += 1

def hook_key_derivation_exit(uc, address, size, user_data):
    """Hook key derivation exit"""
    print("[KEY_DERIV] === Key Derivation Completed ===\n")

# ============================================
# Hook: State Buffer Obfuscation (0x2D9738-0x2D9AB0)
# ============================================

def hook_obfuscation_init(uc, address, size, user_data):
    """Hook state buffer initialization"""
    print("\n[OBFUSCATE] === State Buffer Initialization ===")
    
    # State buffer is at SP + 0xF0 (v39)
    sp = uc.reg_read(UC_ARM64_REG_SP)
    state_buf_addr = sp + 0xF0
    
    print(f"[OBFUSCATE] State buffer @ 0x{state_buf_addr:x}")
    
    collector.current_context['state_buffer_addr'] = state_buf_addr
    collector.call_count['obfuscation_iteration'] = 0

def hook_obfuscation_iteration(uc, address, size, user_data):
    """Hook each obfuscation iteration (0x2D9AB0)"""
    iteration = collector.call_count['obfuscation_iteration']
    
    byte_index = uc.reg_read(UC_ARM64_REG_X5)
    buffer_index = byte_index & 0x1F
    final_byte = uc.reg_read(UC_ARM64_REG_W8) & 0xFF
    
    # Print first 64 iterations or every 32nd
    if iteration < 64 or iteration % 32 == 0:
        print(f"[OBFUSCATE] Iter {iteration:4d}: buf[{buffer_index:2d}] = 0x{final_byte:02x}")
    
    # Capture state buffer every 32 iterations
    if (iteration + 1) % 32 == 0:
        state_buf_addr = collector.current_context.get('state_buffer_addr')
        if state_buf_addr:
            state_data = uc.mem_read(state_buf_addr, 32)
            print(f"[STATE_BUF] Full buffer @ iteration {iteration + 1}:")
            print(f"            {state_data.hex()}")
            
            collector.captured_data['state_buffer_snapshots'].append({
                'iteration': iteration + 1,
                'data': list(state_data)
            })
    
    collector.call_count['obfuscation_iteration'] += 1

# ============================================
# Hook: AES Key Expansion (0x2DBA7C)
# ============================================

def hook_key_expansion_entry(uc, address, size, user_data):
    """Hook key expansion entry"""
    print("\n[KEY_EXP] === AES Key Expansion Started ===")
    
    cipher_ctx = uc.reg_read(UC_ARM64_REG_X0)
    key_schedule_out = uc.reg_read(UC_ARM64_REG_X1)
    master_key = uc.reg_read(UC_ARM64_REG_X2)
    
    key_info = read_vector_info(uc, master_key)
    if key_info and key_info['length'] > 0:
        dump_memory(uc, key_info['begin'], 
                   min(key_info['length'], 64), 
                   "MASTER_KEY")
    
    collector.call_count['key_expansion'] += 1
    collector.call_count['key_exp_round'] = 0

def hook_key_expansion_round(uc, address, size, user_data):
    """Hook each of 256 key expansion rounds (0x2DBEAC)"""
    n256 = uc.reg_read(UC_ARM64_REG_W23)
    accumulator = uc.reg_read(UC_ARM64_REG_W10) & 0xFF
    key_byte = uc.reg_read(UC_ARM64_REG_W22) & 0xFF
    
    # Print key rounds: first 16, every 32nd, and last 16
    if n256 < 16 or n256 % 32 == 0 or n256 > 240:
        print(f"[KEY_EXP] Round {n256:3d}: acc=0x{accumulator:02x}, key_byte=0x{key_byte:02x}")
    
    collector.captured_data['key_expansion_rounds'].append({
        'round': n256,
        'accumulator': accumulator,
        'key_byte': key_byte
    })

def hook_key_expansion_checksum(uc, address, size, user_data):
    """Hook checksum calculation (0x2DC000)"""
    checksum = uc.reg_read(UC_ARM64_REG_W22) & 0xFF
    print(f"[KEY_EXP] Checksum = 0x{checksum:02x}")
    
    # Dump expanded key
    expanded_key_ptr = uc.reg_read(UC_ARM64_REG_X20)
    dump_memory(uc, expanded_key_ptr, 64, "EXPANDED_KEY")
    
    collector.captured_data['key_expansion_rounds'].append({
        'type': 'checksum',
        'value': checksum
    })

def hook_key_expansion_exit(uc, address, size, user_data):
    """Hook key expansion exit"""
    print("[KEY_EXP] === Key Expansion Completed ===\n")

# ============================================
# Hook: S-box Substitution (0x2D44C0)
# ============================================

def hook_sbox_entry(uc, address, size, user_data):
    """Hook S-box function entry"""
    print("\n[SBOX] === SubBytes Operation ===")
    collector.call_count['sbox_lookup'] = 0

def hook_sbox_lookup(uc, address, size, user_data):
    """Hook individual S-box lookup (0x2D4748)"""
    input_byte = uc.reg_read(UC_ARM64_REG_W10) & 0xFF
    high_nibble = input_byte >> 4
    low_nibble = input_byte & 0x0F
    
    # Store for onLeave processing
    collector.current_context['sbox_input'] = input_byte
    collector.current_context['sbox_high'] = high_nibble
    collector.current_context['sbox_low'] = low_nibble

def hook_sbox_lookup_exit(uc, address, size, user_data):
    """Hook S-box lookup return"""
    output_byte = uc.reg_read(UC_ARM64_REG_X0) & 0xFF
    
    input_byte = collector.current_context.get('sbox_input', 0)
    high = collector.current_context.get('sbox_high', 0)
    low = collector.current_context.get('sbox_low', 0)
    
    count = collector.call_count['sbox_lookup']
    if count < 16:  # Only print first 16
        print(f"[SBOX] Input=0x{input_byte:02x} [{high:x},{low:x}] -> Output=0x{output_byte:02x}")
    
    collector.captured_data['sbox_lookups'].append({
        'input': input_byte,
        'high': high,
        'low': low,
        'output': output_byte
    })
    
    collector.call_count['sbox_lookup'] += 1

# ============================================
# Hook: AddRoundKey (0x2DC970)
# ============================================

def hook_add_round_key_entry(uc, address, size, user_data):
    """Hook AddRoundKey entry"""
    print("\n[ADD_KEY] === AddRoundKey Operation ===")
    collector.call_count['add_round_key'] = 0

def hook_add_round_key_xor(uc, address, size, user_data):
    """Hook individual XOR operation (0x2DCCA8)"""
    state_byte = uc.reg_read(UC_ARM64_REG_W9) & 0xFF
    key_byte = uc.reg_read(UC_ARM64_REG_W8) & 0xFF
    
    collector.current_context['ark_state'] = state_byte
    collector.current_context['ark_key'] = key_byte

def hook_add_round_key_xor_exit(uc, address, size, user_data):
    """Hook XOR return"""
    result = uc.reg_read(UC_ARM64_REG_X0) & 0xFF
    
    state = collector.current_context.get('ark_state', 0)
    key = collector.current_context.get('ark_key', 0)
    
    count = collector.call_count['add_round_key']
    if count < 16:  # Print first 16
        print(f"[ADD_KEY] State=0x{state:02x} XOR Key=0x{key:02x} = 0x{result:02x}")
    
    collector.captured_data['round_keys'].append({
        'state': state,
        'key': key,
        'result': result
    })
    
    collector.call_count['add_round_key'] += 1

# ============================================
# Hook: RC4 Keystream (0x2D050C)
# ============================================

def hook_rc4_entry(uc, address, size, user_data):
    """Hook RC4 entry"""
    print("\n[RC4] === RC4 Keystream Generation ===")
    collector.call_count['rc4_iteration'] = 0

def hook_rc4_init(uc, address, size, user_data):
    """Hook RC4 initialization (0x2D0570)"""
    init_j = -53
    print(f"[RC4] Initial j = {init_j} (0x{init_j & 0xFF:02x})")

def hook_rc4_prga(uc, address, size, user_data):
    """Hook RC4 PRGA iteration (0x2D0694)"""
    i = uc.reg_read(UC_ARM64_REG_W23) & 0xFF
    j = uc.reg_read(UC_ARM64_REG_W24) & 0xFF
    S_i = uc.reg_read(UC_ARM64_REG_W8) & 0xFF
    
    count = collector.call_count['rc4_iteration']
    if count < 32:  # Print first 32
        print(f"[RC4] i={i:3d}, j={j:3d}, S[i]=0x{S_i:02x}")
    
    collector.captured_data['rc4_states'].append({
        'iteration': count,
        'i': i,
        'j': j,
        'S_i': S_i
    })
    
    collector.call_count['rc4_iteration'] += 1

# ============================================
# Main Hook Installation
# ============================================

def install_hooks(uc, base_addr=0):
    """
    Install all hooks for AES analysis
    
    Args:
        uc: Unicorn engine instance
        base_addr: Base address offset (if code is relocated)
    """
    
    print("[+] Installing Unicorn hooks for AES analysis...")
    
    # Main function hooks
    uc.hook_add(UC_HOOK_CODE, hook_main_entry, 
                begin=base_addr + 0x2D967C, end=base_addr + 0x2D967C)
    uc.hook_add(UC_HOOK_CODE, hook_main_exit, 
                begin=base_addr + 0x2DA014 - 4, end=base_addr + 0x2DA014 - 4)
    
    # Key derivation hooks
    uc.hook_add(UC_HOOK_CODE, hook_key_derivation_entry, 
                begin=base_addr + 0x2DA014, end=base_addr + 0x2DA014)
    uc.hook_add(UC_HOOK_CODE, hook_key_derivation_seed, 
                begin=base_addr + 0x2DA064, end=base_addr + 0x2DA064)
    uc.hook_add(UC_HOOK_CODE, hook_key_derivation_round, 
                begin=base_addr + 0x2DA248, end=base_addr + 0x2DA248)
    
    # Obfuscation hooks
    uc.hook_add(UC_HOOK_CODE, hook_obfuscation_init, 
                begin=base_addr + 0x2D9738, end=base_addr + 0x2D9738)
    uc.hook_add(UC_HOOK_CODE, hook_obfuscation_iteration, 
                begin=base_addr + 0x2D9AB0, end=base_addr + 0x2D9AB0)
    
    # Key expansion hooks
    uc.hook_add(UC_HOOK_CODE, hook_key_expansion_entry, 
                begin=base_addr + 0x2DBA7C, end=base_addr + 0x2DBA7C)
    uc.hook_add(UC_HOOK_CODE, hook_key_expansion_round, 
                begin=base_addr + 0x2DBEAC, end=base_addr + 0x2DBEAC)
    uc.hook_add(UC_HOOK_CODE, hook_key_expansion_checksum, 
                begin=base_addr + 0x2DC000, end=base_addr + 0x2DC000)
    
    # S-box hooks
    uc.hook_add(UC_HOOK_CODE, hook_sbox_entry, 
                begin=base_addr + 0x2D44C0, end=base_addr + 0x2D44C0)
    uc.hook_add(UC_HOOK_CODE, hook_sbox_lookup, 
                begin=base_addr + 0x2D4748, end=base_addr + 0x2D4748)
    # Note: Need to hook return of sbox_lookup function
    
    # AddRoundKey hooks
    uc.hook_add(UC_HOOK_CODE, hook_add_round_key_entry, 
                begin=base_addr + 0x2DC9FC, end=base_addr + 0x2DC9FC)
    uc.hook_add(UC_HOOK_CODE, hook_add_round_key_xor, 
                begin=base_addr + 0x2DCCA8, end=base_addr + 0x2DCCA8)
    
    # RC4 hooks
    uc.hook_add(UC_HOOK_CODE, hook_rc4_entry, 
                begin=base_addr + 0x2D050C, end=base_addr + 0x2D050C)
    uc.hook_add(UC_HOOK_CODE, hook_rc4_init, 
                begin=base_addr + 0x2D0570, end=base_addr + 0x2D0570)
    uc.hook_add(UC_HOOK_CODE, hook_rc4_prga, 
                begin=base_addr + 0x2D0694, end=base_addr + 0x2D0694)
    
    print("[+] All hooks installed successfully!\n")

# ============================================
# Example Usage
# ============================================

def example_usage():
    """
    Example of how to use these hooks with Unicorn
    """
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
    
    # Initialize Unicorn
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    
    # Load your binary and setup memory here
    # ...
    
    # Install hooks
    base_addr = 0  # or your loaded base address
    install_hooks(uc, base_addr)
    
    # Setup parameters in registers
    # uc.reg_write(UC_ARM64_REG_X0, cipher_handle_addr)
    # uc.reg_write(UC_ARM64_REG_X1, plaintext_addr)
    # uc.reg_write(UC_ARM64_REG_X2, key_addr)
    # uc.reg_write(UC_ARM64_REG_X3, iv_addr)
    # uc.reg_write(UC_ARM64_REG_X8, output_addr)
    
    # Start emulation
    # uc.emu_start(base_addr + 0x2D967C, base_addr + 0x2D967C + 0x998)
    
    # Save collected data
    collector.save_to_file('unicorn_aes_analysis.json')
    
    print("\n[+] Analysis complete!")
    print(f"[+] Main function called: {collector.call_count['main']} times")
    print(f"[+] Obfuscation iterations: {collector.call_count['obfuscation_iteration']}")
    print(f"[+] S-box lookups: {collector.call_count['sbox_lookup']}")
    print(f"[+] Key expansion rounds: {len(collector.captured_data['key_expansion_rounds'])}")

if __name__ == '__main__':
    print("Unicorn AES Hook Script")
    print("Usage: Import this module and call install_hooks(uc, base_addr)")
    print("\nExample:")
    print("  from unicorn_aes_hooks import install_hooks, collector")
    print("  install_hooks(uc, 0x0)")
    print("  # Run your emulation")
    print("  collector.save_to_file('results.json')")

