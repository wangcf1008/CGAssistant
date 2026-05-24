"""
CGAssistant 结构dump脚本
========================
针对已发现的名字位置，大范围dump并搜索所有已知数值。

使用方法：
1. 以管理员身份打开 CMD
2. 运行: python dump.py
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

def main():
    print("=" * 65)
    print("  CGAssistant 结构dump脚本")
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

    print(f"  基址: 0x{base_addr:X}")

    # 上次发现的关键地址
    targets = [
        ("结构A", 0xED3D80 - 0x800, 0x4000, 0xED3D80, 0xED4028),
        ("结构B", 0x1074C00 - 0x800, 0x4000, 0x1074E9C, 0x1074CF8),
    ]

    known_values = {
        "level": level,
        "HP": hp,
        "MaxHP": maxhp,
        "MP": mp,
        "MaxMP": maxmp,
    }

    for name, dump_start, dump_size, level_addr, name_addr in targets:
        print(f"\n{'='*65}")
        print(f"  {name}: dump 0x{dump_start:X} ~ 0x{dump_start+dump_size:X}")
        print(f"  level位置: 0x{level_addr:X}, 名字位置: 0x{name_addr:X}")
        print(f"{'='*65}")

        data = read_mem(handle, dump_start, dump_size)
        if data is None:
            print("  无法读取")
            continue

        # 搜索所有已知值 (普通int)
        print(f"\n  --- 搜索普通int ---")
        for vname, vval in known_values.items():
            vbytes = struct.pack('<i', vval)
            pos = 0
            while True:
                idx = data.find(vbytes, pos)
                if idx == -1:
                    break
                abs_addr = dump_start + idx
                rel_level = idx - (level_addr - dump_start)
                rel_name = idx - (name_addr - dump_start)
                print(f"  {vname}={vval}: 0x{abs_addr:X} (距level {rel_level:+d}, 距名字 {rel_name:+d})")
                pos = idx + 1

        # 搜索 short 值
        print(f"\n  --- 搜索short值 ---")
        for vname, vval in known_values.items():
            if vval > 32767 or vval < -32768:
                continue
            vbytes = struct.pack('<h', vval)
            pos = 0
            count = 0
            while count < 20:
                idx = data.find(vbytes, pos)
                if idx == -1:
                    break
                # 检查对齐 (2字节)
                if idx % 2 == 0:
                    abs_addr = dump_start + idx
                    rel_name = idx - (name_addr - dump_start)
                    # 只显示距离名字较近的
                    if -0x400 < rel_name < 0x400:
                        print(f"  {vname}={vval}(short): 0x{abs_addr:X} (距名字 {rel_name:+d})")
                pos = idx + 1
                count += 1

        # 搜索 XOR 编码值
        print(f"\n  --- 搜索XOR编码值 ---")
        for vname, vval in known_values.items():
            for i in range(0, len(data) - 12, 4):
                k1, k2 = struct.unpack('<ii', data[i:i+8])
                if (k1 ^ k2) == vval and k1 != 0 and k2 != 0:
                    abs_addr = dump_start + i
                    rel_name = i - (name_addr - dump_start)
                    print(f"  {vname}={vval}(XOR): 0x{abs_addr:X} (距名字 {rel_name:+d}), k1=0x{k1:X}, k2=0x{k2:X}")

        # dump 结构的关键区域 (以level为锚点，前后各0x100)
        level_off = level_addr - dump_start
        if 0 <= level_off < dump_size:
            print(f"\n  --- 以level为锚点 dump (+0x100 ~ -0x100) ---")
            start = max(0, level_off - 0x100)
            end = min(dump_size, level_off + 0x100)
            for i in range(start, end, 16):
                chunk = data[i:i+16]
                hex_part = ' '.join(f'{b:02X}' for b in chunk)
                ints = []
                for k in range(0, min(16, len(chunk)), 4):
                    if k+4 <= len(chunk):
                        iv = struct.unpack('<i', chunk[k:k+4])[0]
                        label = ""
                        for vname, vval in known_values.items():
                            if iv == vval:
                                label = f" <<<{vname}>>>"
                                break
                        ints.append(f"{iv}{label}")
                ints_str = ' | '.join(ints)
                abs_addr = dump_start + i
                rel = i - level_off
                print(f"  0x{abs_addr:X} ({rel:+5d}): {hex_part}")
                print(f"    ints: {ints_str}")

        # 也以名字为锚点 dump
        name_off = name_addr - dump_start
        if 0 <= name_off < dump_size:
            print(f"\n  --- 以名字为锚点 dump (前0x200) ---")
            start = max(0, name_off - 0x200)
            end = min(dump_size, name_off + 0x20)
            for i in range(start, end, 16):
                chunk = data[i:i+16]
                hex_part = ' '.join(f'{b:02X}' for b in chunk)
                abs_addr = dump_start + i
                rel = i - name_off
                print(f"  0x{abs_addr:X} ({rel:+5d}): {hex_part}")

    # ==========================================
    # 搜索全局指针
    # ==========================================
    print(f"\n{'='*65}")
    print(f"  搜索 .data 段中的全局指针")
    print(f"{'='*65}")

    # 对于结构A, level在0xED3D80, 名字在0xED4028
    # 结构可能从 0xED3D80 - 4 = 0xED3D7C 开始 (如果level在偏移+4)
    # 或者从更早开始
    # 搜索指向 0xED3D00 ~ 0xED3D80 范围的指针
    struct_a_candidates = [0xED3D7C, 0xED3D80, 0xED3D00, 0xED3C00, 0xED3B00]
    print(f"\n  结构A: 搜索指向以下地址的指针:")
    for target in struct_a_candidates:
        ptr_bytes = struct.pack('<I', target)
        for offset in range(0, image_size, 65536):
            read_size = min(65536 + 4, image_size - offset)
            d = read_mem(handle, base_addr + offset, read_size)
            if d is None:
                continue
            pos = 0
            while True:
                idx = d.find(ptr_bytes, pos)
                if idx == -1:
                    break
                ptr_addr = base_addr + offset + idx
                ptr_offset = ptr_addr - base_addr
                print(f"    0x{ptr_addr:X} (偏移 0x{ptr_offset:X}) -> 0x{target:X}")
                pos = idx + 1
                if pos > 5:
                    break

    # 对于结构B, 名字在0x1074CF8, level在0x1074E9C
    # 结构可能从 0x1074C00 开始
    struct_b_candidates = [0x1074C00, 0x1074BF0, 0x1074BE0]
    print(f"\n  结构B: 搜索指向以下地址的指针:")
    for target in struct_b_candidates:
        ptr_bytes = struct.pack('<I', target)
        for offset in range(0, image_size, 65536):
            read_size = min(65536 + 4, image_size - offset)
            d = read_mem(handle, base_addr + offset, read_size)
            if d is None:
                continue
            pos = 0
            while True:
                idx = d.find(ptr_bytes, pos)
                if idx == -1:
                    break
                ptr_addr = base_addr + offset + idx
                ptr_offset = ptr_addr - base_addr
                print(f"    0x{ptr_addr:X} (偏移 0x{ptr_offset:X}) -> 0x{target:X}")
                pos = idx + 1
                if pos > 5:
                    break

    CloseHandle(handle)
    input("\n按回车退出...")


if __name__ == "__main__":
    main()
