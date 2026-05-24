"""
CGAssistant 结构探测脚本
========================
以角色名位置为锚点，在附近搜索已知数值，反推 playerbase_t 的真实布局。

使用方法：
1. 以管理员身份打开 CMD
2. 运行: python probe.py
3. 输入当前角色的精确数值
"""

import ctypes
import ctypes.wintypes as wintypes
import struct
import os

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]
class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]
class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE
CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL
ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL
OpenProcessToken = advapi32.OpenProcessToken
OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
OpenProcessToken.restype = wintypes.BOOL
LookupPrivilegeValueA = advapi32.LookupPrivilegeValueA
LookupPrivilegeValueA.argtypes = [wintypes.LPCSTR, wintypes.LPCSTR, ctypes.POINTER(LUID)]
LookupPrivilegeValueA.restype = wintypes.BOOL
AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES), wintypes.DWORD, ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.POINTER(wintypes.DWORD)]
AdjustTokenPrivileges.restype = wintypes.BOOL
GetCurrentProcess = kernel32.GetCurrentProcess
GetCurrentProcess.argtypes = []
GetCurrentProcess.restype = wintypes.HANDLE
FindWindowA = ctypes.windll.user32.FindWindowA
FindWindowA.argtypes = [wintypes.LPCSTR, wintypes.LPCSTR]
FindWindowA.restype = wintypes.HWND
GetWindowThreadProcessId = ctypes.windll.user32.GetWindowThreadProcessId
GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
GetWindowThreadProcessId.restype = wintypes.DWORD
EnumProcessModules = ctypes.windll.psapi.EnumProcessModules
EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
EnumProcessModules.restype = wintypes.BOOL
GetModuleBaseNameA = ctypes.windll.psapi.GetModuleBaseNameA
GetModuleBaseNameA.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPCSTR, wintypes.DWORD]
GetModuleBaseNameA.restype = wintypes.DWORD

class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p), ("SizeOfImage", wintypes.DWORD), ("EntryPoint", ctypes.c_void_p)]

GetModuleInformation = ctypes.windll.psapi.GetModuleInformation
GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE, ctypes.POINTER(MODULEINFO), wintypes.DWORD]
GetModuleInformation.restype = wintypes.BOOL

def enable_debug_privilege():
    hToken = wintypes.HANDLE()
    if not OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(hToken)):
        return False
    luid = LUID()
    if not LookupPrivilegeValueA(None, b"SeDebugPrivilege", ctypes.byref(luid)):
        CloseHandle(hToken)
        return False
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), 0, None, None)
    err = ctypes.get_last_error()
    CloseHandle(hToken)
    return err == 0

def read_mem(handle, address, size):
    buf = ctypes.create_string_buffer(size)
    bytesRead = ctypes.c_size_t()
    if not ReadProcessMemory(handle, address, buf, size, ctypes.byref(bytesRead)):
        return None
    return buf.raw[:bytesRead.value]

def read_int(handle, address):
    data = read_mem(handle, address, 4)
    if data is None or len(data) < 4:
        return None
    return struct.unpack('<i', data)[0]

def read_uint(handle, address):
    data = read_mem(handle, address, 4)
    if data is None or len(data) < 4:
        return None
    return struct.unpack('<I', data)[0]

def read_short(handle, address):
    data = read_mem(handle, address, 2)
    if data is None or len(data) < 2:
        return None
    return struct.unpack('<h', data)[0]

def read_string(handle, address, max_len=256):
    data = read_mem(handle, address, max_len)
    if data is None:
        return ""
    try:
        idx = data.index(0)
        data = data[:idx]
    except ValueError:
        pass
    try:
        return data.decode('gbk')
    except Exception:
        try:
            return data.decode('latin-1')
        except Exception:
            return ""

def read_xor_value(handle, address):
    data = read_mem(handle, address, 16)
    if data is None or len(data) < 12:
        return None
    unknown, key1, key2 = struct.unpack('<iii', data[:12])
    return key1 ^ key2

def find_name_locations(handle, base_addr, image_size, name_str):
    name_bytes = name_str.encode('gbk')
    results = []
    chunk_size = 65536
    for offset in range(0, image_size, chunk_size):
        read_size = min(chunk_size + len(name_bytes), image_size - offset)
        data = read_mem(handle, base_addr + offset, read_size)
        if data is None:
            continue
        pos = 0
        while True:
            idx = data.find(name_bytes, pos)
            if idx == -1:
                break
            results.append(base_addr + offset + idx)
            pos = idx + 1
    return results

def find_int_in_data(data, target, base_offset=0):
    target_bytes = struct.pack('<i', target)
    results = []
    pos = 0
    while True:
        idx = data.find(target_bytes, pos)
        if idx == -1:
            break
        results.append(base_offset + idx)
        pos = idx + 1
    return results

def find_xor_in_data(data, target, base_offset=0):
    results = []
    for i in range(0, len(data) - 12, 4):
        k1, k2 = struct.unpack('<ii', data[i:i+8])
        if (k1 ^ k2) == target and k1 != 0 and k2 != 0:
            results.append((base_offset + i, k1, k2))
    return results

def main():
    print("=" * 65)
    print("  CGAssistant 结构探测脚本")
    print("=" * 65)

    print("\n  请输入角色当前精确数值：")
    level = int(input("  等级: ").strip() or "0")
    hp = int(input("  当前HP: ").strip() or "0")
    maxhp = int(input("  最大HP: ").strip() or "0")
    mp = int(input("  当前MP: ").strip() or "0")
    maxmp = int(input("  最大MP: ").strip() or "0")
    player_name = input("  角色名: ").strip()

    print("\n  正在启用调试权限...")
    enable_debug_privilege()

    print("  正在查找游戏进程...")
    hwnd = FindWindowA("魔力宝贝".encode('gbk'), None)
    if not hwnd:
        hwnd = FindWindowA("魔力宝贝".encode('utf-8'), None)
    if not hwnd:
        print("  未找到游戏窗口！")
        input("按回车退出...")
        return

    pid = wintypes.DWORD()
    GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    pid = pid.value

    handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        handle = OpenProcess(PROCESS_VM_READ, False, pid)
    if not handle:
        print("  无法打开进程")
        input("按回车退出...")
        return

    hModules = (wintypes.HMODULE * 1024)()
    cbNeeded = wintypes.DWORD()
    base_addr = 0x400000
    image_size = 0x1400000

    if EnumProcessModules(handle, hModules, ctypes.sizeof(hModules), ctypes.byref(cbNeeded)):
        base_addr = hModules[0]
        mi = MODULEINFO()
        if GetModuleInformation(handle, base_addr, ctypes.byref(mi), ctypes.sizeof(mi)):
            image_size = mi.SizeOfImage

    print(f"  基址: 0x{base_addr:X}, 镜像大小: 0x{image_size:X}")

    # 找到角色名位置
    name_locs = find_name_locations(handle, base_addr, image_size, player_name)
    print(f"\n  角色名 '{player_name}' 出现在 {len(name_locs)} 处:")
    for i, loc in enumerate(name_locs):
        print(f"    [{i}] 0x{loc:X} (偏移 0x{loc - base_addr:X})")

    # 对每个名字位置，dump 前后 0x1000 字节
    SEARCH_RANGE = 0x1000

    for ni, name_addr in enumerate(name_locs):
        print(f"\n{'='*65}")
        print(f"  分析名字位置 [{ni}]: 0x{name_addr:X}")
        print(f"{'='*65}")

        dump_start = max(base_addr, name_addr - SEARCH_RANGE)
        dump_end = min(base_addr + image_size, name_addr + SEARCH_RANGE)
        dump_size = dump_end - dump_start
        dump_data = read_mem(handle, dump_start, dump_size)

        if dump_data is None:
            print("  无法读取内存")
            continue

        name_offset_in_dump = name_addr - dump_start

        # 搜索普通 int 值
        print(f"\n  --- 搜索普通int值 ---")
        for val_name, val in [("level", level), ("HP", hp), ("MaxHP", maxhp), ("MP", mp), ("MaxMP", maxmp)]:
            found = find_int_in_data(dump_data, val, 0)
            for off in found:
                abs_addr = dump_start + off
                rel_to_name = off - name_offset_in_dump
                print(f"  {val_name}={val}: 地址 0x{abs_addr:X} (距名字 {rel_to_name:+d} = 0x{rel_to_name & 0xFFFF:X})")

        # 搜索 XOR 编码值
        print(f"\n  --- 搜索XOR编码值 ---")
        for val_name, val in [("HP", hp), ("MaxHP", maxhp), ("MP", mp), ("MaxMP", maxmp)]:
            found = find_xor_in_data(dump_data, val, 0)
            for off, k1, k2 in found:
                abs_addr = dump_start + off
                rel_to_name = off - name_offset_in_dump
                print(f"  {val_name}={val}(XOR): 地址 0x{abs_addr:X} (距名字 {rel_to_name:+d} = 0x{rel_to_name & 0xFFFF:X}), key1=0x{k1:X}, key2=0x{k2:X}")

        # 尝试找到 playerbase 指针
        # 如果名字地址在堆上，那么在 .data 段中应该有指针指向它
        print(f"\n  --- 搜索指向名字附近的指针 ---")
        # 搜索指向 name_addr - N 的指针 (N = 0 到 0x400)
        ptr_targets = set()
        for n in range(0, 0x400, 4):
            ptr_targets.add(name_addr - n)

        for ptr_target in list(ptr_targets)[:100]:
            ptr_bytes = struct.pack('<I', ptr_target)
            for offset in range(0, image_size, 65536):
                read_size = min(65536 + 4, image_size - offset)
                data = read_mem(handle, base_addr + offset, read_size)
                if data is None:
                    continue
                pos = 0
                while True:
                    idx = data.find(ptr_bytes, pos)
                    if idx == -1:
                        break
                    ptr_addr = base_addr + offset + idx
                    ptr_offset = ptr_addr - base_addr
                    name_offset_in_struct = name_addr - ptr_target
                    print(f"  指针 0x{ptr_addr:X} (偏移 0x{ptr_offset:X}) -> 0x{ptr_target:X} (名字在结构内偏移 +0x{name_offset_in_struct:X})")
                    pos = idx + 1
                    if pos > 10:
                        break
                if pos > 10:
                    break

    # ==========================================
    # 额外策略: 在整个镜像中搜索指针指向名字地址
    # ==========================================
    print(f"\n{'='*65}")
    print(f"  在 .data 段搜索指向角色名的全局指针")
    print(f"{'='*65}")

    for name_addr in name_locs:
        ptr_bytes = struct.pack('<I', name_addr)
        found_ptrs = []
        for offset in range(0, image_size, 65536):
            read_size = min(65536 + 4, image_size - offset)
            data = read_mem(handle, base_addr + offset, read_size)
            if data is None:
                continue
            pos = 0
            while True:
                idx = data.find(ptr_bytes, pos)
                if idx == -1:
                    break
                ptr_addr = base_addr + offset + idx
                found_ptrs.append(ptr_addr)
                pos = idx + 1
                if len(found_ptrs) >= 20:
                    break
            if len(found_ptrs) >= 20:
                break

        if found_ptrs:
            print(f"\n  名字地址 0x{name_addr:X} 的指针:")
            for pa in found_ptrs:
                print(f"    0x{pa:X} (偏移 0x{pa - base_addr:X})")

                # 如果这是 g_player_name，那么附近的指针可能是 g_playerBase 等
                # dump 这个指针附近 0x200 字节
                nearby = read_mem(handle, max(base_addr, pa - 0x100), 0x300)
                if nearby:
                    nearby_base = max(base_addr, pa - 0x100)
                    print(f"    --- 附近指针 (0x{nearby_base:X} ~ 0x{nearby_base + 0x300:X}) ---")
                    for i in range(0, len(nearby), 4):
                        val = struct.unpack('<I', nearby[i:i+4])[0]
                        if val > 0x10000 and val < 0x7FFFFFFF:
                            # 可能是一个指针
                            # 尝试读取它指向的内容
                            target_data = read_mem(handle, val, 8)
                            if target_data:
                                first_int = struct.unpack('<i', target_data[:4])[0]
                                # 检查是否可能是 level
                                if first_int == level:
                                    print(f"    偏移+0x{i:X}: 0x{val:X} -> 第一个int={first_int} ★★★ 可能是 playerBase 指针! level匹配!")
                                    # 进一步验证
                                    hp_check = None
                                    try:
                                        xor_data = read_mem(handle, val + 24, 16)
                                        if xor_data and len(xor_data) >= 12:
                                            k1, k2 = struct.unpack('<ii', xor_data[:8])
                                            hp_check = k1 ^ k2
                                    except:
                                        pass
                                    print(f"      尝试偏移+24 XOR HP: {hp_check}")

                                    # 也尝试普通int
                                    hp_plain = read_int(handle, val + 24)
                                    maxhp_plain = read_int(handle, val + 28)
                                    print(f"      尝试偏移+24 普通int: {hp_plain}, +28: {maxhp_plain}")

                                    # dump 这个结构的前 0x100 字节
                                    struct_data = read_mem(handle, val, 0x400)
                                    if struct_data:
                                        print(f"      --- 结构前0x100字节 ---")
                                        for j in range(0, min(0x100, len(struct_data)), 16):
                                            chunk = struct_data[j:j+16]
                                            hex_part = ' '.join(f'{b:02X}' for b in chunk)
                                            # 尝试解读每个4字节为int
                                            ints = []
                                            for k in range(0, min(16, len(chunk)), 4):
                                                if k+4 <= len(chunk):
                                                    iv = struct.unpack('<i', chunk[k:k+4])[0]
                                                    ints.append(f"{iv}")
                                            ints_str = ' | '.join(ints)
                                            print(f"      +0x{j:03X}: {hex_part}  [{ints_str}]")

                                        # 搜索已知值在结构中的位置
                                        print(f"\n      --- 在结构中搜索已知值 ---")
                                        for val_name, val in [("level", level), ("HP", hp), ("MaxHP", maxhp), ("MP", mp), ("MaxMP", maxmp)]:
                                            val_bytes = struct.pack('<i', val)
                                            pos2 = 0
                                            while True:
                                                idx2 = struct_data.find(val_bytes, pos2)
                                                if idx2 == -1:
                                                    break
                                                print(f"      {val_name}={val} 在偏移 +0x{idx2:X} (普通int)")
                                                pos2 = idx2 + 1

                                        # 搜索XOR编码
                                        for val_name, val in [("HP", hp), ("MaxHP", maxhp), ("MP", mp), ("MaxMP", maxmp)]:
                                            for j in range(0, len(struct_data) - 12, 4):
                                                k1, k2 = struct.unpack('<ii', struct_data[j:j+8])
                                                if (k1 ^ k2) == val and k1 != 0 and k2 != 0:
                                                    print(f"      {val_name}={val}(XOR) 在偏移 +0x{j:X}, k1=0x{k1:X}, k2=0x{k2:X}")

                                elif 0 < first_int < 1000:
                                    target_name = read_string(handle, val + 256, 17)
                                    if target_name == player_name:
                                        print(f"    偏移+0x{i:X}: 0x{val:X} -> +256处名字='{target_name}' ★★★ playerBase!")

    CloseHandle(handle)
    input("\n按回车退出...")


if __name__ == "__main__":
    main()
