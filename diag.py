"""
CGAssistant 外部读取测试脚本 - 诊断模式
====================================
跳过在线检查，直接尝试读取并显示原始数据，帮助确定正确的偏移量。

使用方法：
1. 以管理员身份打开 CMD
2. 运行: python diag.py
"""

import ctypes
import ctypes.wintypes as wintypes
import struct
import time
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
        return None, None, None, None
    unknown, key1, key2 = struct.unpack('<iii', data[:12])
    refcount = data[12] if len(data) > 12 else None
    decoded = key1 ^ key2
    return decoded, key1, key2, refcount

def hex_dump(handle, address, size=256):
    data = read_mem(handle, address, size)
    if data is None:
        return "  (无法读取)"
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"  {address+i:08X}: {hex_part:<48s} {ascii_part}")
    return '\n'.join(lines)

def scan_for_string(handle, base_addr, image_size, target_str, max_results=10):
    results = []
    target_bytes = target_str.encode('gbk')
    chunk_size = 65536
    for offset in range(0, image_size, chunk_size):
        read_size = min(chunk_size + len(target_bytes), image_size - offset)
        data = read_mem(handle, base_addr + offset, read_size)
        if data is None:
            continue
        pos = 0
        while True:
            idx = data.find(target_bytes, pos)
            if idx == -1:
                break
            addr = base_addr + offset + idx
            results.append(addr)
            if len(results) >= max_results:
                return results
            pos = idx + 1
    return results

def main():
    print("=" * 65)
    print("  CGAssistant 诊断模式 - 帮助确定正确的内存偏移")
    print("=" * 65)

    print("\n  请输入你的角色名（用于在内存中搜索定位）：")
    player_name_input = input("  角色名: ").strip()
    if not player_name_input:
        print("  未输入角色名，将跳过内存搜索")
        player_name_input = None

    print("\n  正在启用调试权限...")
    if enable_debug_privilege():
        print("  调试权限已启用")
    else:
        print("  调试权限启用失败")

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
        print(f"  无法打开进程 (Error={ctypes.get_last_error()})")
        input("按回车退出...")
        return

    hModules = (wintypes.HMODULE * 1024)()
    cbNeeded = wintypes.DWORD()
    base_addr = 0x400000
    image_size = 0x1400000

    if EnumProcessModules(handle, hModules, ctypes.sizeof(hModules), ctypes.byref(cbNeeded)):
        base_addr = hModules[0]
        modName = ctypes.create_string_buffer(260)
        GetModuleBaseNameA(handle, base_addr, modName, 260)
        exe_name = modName.value.decode('latin-1', errors='replace')

        MODULEINFO = ctypes.Structure
        class MODULEINFO(ctypes.Structure):
            _fields_ = [("lpBaseOfDll", ctypes.c_void_p), ("SizeOfImage", wintypes.DWORD), ("EntryPoint", ctypes.c_void_p)]

        GetModuleInformation = ctypes.windll.psapi.GetModuleInformation
        GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE, ctypes.POINTER(MODULEINFO), wintypes.DWORD]
        GetModuleInformation.restype = wintypes.BOOL

        mi = MODULEINFO()
        if GetModuleInformation(handle, base_addr, ctypes.byref(mi), ctypes.sizeof(mi)):
            image_size = mi.SizeOfImage

        print(f"  找到进程: {exe_name}, PID={pid}")
        print(f"  基址: 0x{base_addr:X}, 镜像大小: 0x{image_size:X} ({image_size//1024//1024}MB)")
    else:
        print(f"  找到进程 PID={pid}, 使用默认基址 0x400000")

    print("\n" + "=" * 65)
    print("  第一步：检查已知偏移")
    print("=" * 65)

    offsets_to_check = {
        "cg_se_3000": {
            "g_is_ingame (0xA15190)": 0xA15190,
            "g_player_name (0xA150B0)": 0xA150B0,
            "g_playerBase** (0xCAEF88)": 0xCAEF88,
            "g_world_status XOR (0xC0C350)": 0xC0C350,
            "g_game_status XOR (0xC0C360)": 0xC0C360,
        },
        "cg_item_6000": {
            "g_is_ingame (0xBDBA78)": 0xBDBA78,
            "g_player_name (0xBDB998)": 0xBDB998,
            "g_playerBase* (0xE12C30)": 0xE12C30,
            "g_world_status int (0xE1E000)": 0xE1E000,
            "g_game_status int (0xE1DFFC)": 0xE1DFFC,
        },
    }

    for ver_name, addrs in offsets_to_check.items():
        print(f"\n  --- {ver_name} 偏移 ---")
        for name, offset in addrs.items():
            addr = base_addr + offset
            if "XOR" in name:
                decoded, k1, k2, ref = read_xor_value(handle, addr)
                raw_int = read_int(handle, addr)
                print(f"  {name}")
                print(f"    地址: 0x{addr:X}, 原始int: {raw_int}")
                print(f"    XOR: key1=0x{k1:X if k1 else 0}, key2=0x{k2:X if k2 else 0}, 解码={decoded}")
            elif "name" in name.lower():
                val = read_string(handle, addr, 32)
                print(f"  {name}")
                print(f"    地址: 0x{addr:X}, 值: '{val}'")
            elif "playerBase" in name:
                val = read_uint(handle, addr)
                print(f"  {name}")
                print(f"    地址: 0x{addr:X}, 指针值: 0x{val:X if val else 0}")
                if val and val > base_addr and val < base_addr + image_size + 0x10000000:
                    if "**" in name:
                        val2 = read_uint(handle, val)
                        print(f"    -> 二次解引用: 0x{val2:X if val2 else 0}")
                        if val2:
                            name_at_base = read_string(handle, val2 + 256, 17)
                            hp_dec, _, _, _ = read_xor_value(handle, val2 + 24)
                            maxhp_dec, _, _, _ = read_xor_value(handle, val2 + 40)
                            print(f"    -> 偏移+256名字: '{name_at_base}'")
                            print(f"    -> 偏移+24 HP(解码): {hp_dec}")
                            print(f"    -> 偏移+40 MaxHP(解码): {maxhp_dec}")
                    else:
                        name_at_base = read_string(handle, val + 256, 17)
                        hp_dec, _, _, _ = read_xor_value(handle, val + 24)
                        maxhp_dec, _, _, _ = read_xor_value(handle, val + 40)
                        print(f"    -> 偏移+256名字: '{name_at_base}'")
                        print(f"    -> 偏移+24 HP(解码): {hp_dec}")
                        print(f"    -> 偏移+40 MaxHP(解码): {maxhp_dec}")
            else:
                val = read_int(handle, addr)
                print(f"  {name}")
                print(f"    地址: 0x{addr:X}, 值: {val}")

    if player_name_input:
        print("\n" + "=" * 65)
        print("  第二步：在内存中搜索角色名")
        print("=" * 65)
        print(f"  搜索: '{player_name_input}' ...")
        print(f"  (这可能需要几十秒，请耐心等待)")

        results = scan_for_string(handle, base_addr, image_size, player_name_input, max_results=20)

        if results:
            print(f"\n  找到 {len(results)} 处匹配:")
            for i, addr in enumerate(results):
                context = hex_dump(handle, max(0, addr - 32), 96)
                print(f"\n  [{i}] 地址: 0x{addr:X}")
                print(context)

                if i < 5:
                    print(f"\n  --- 尝试作为 playerbase_t 解读 (假设名字在偏移+256) ---")
                    candidate_base = addr - 256
                    if candidate_base > base_addr:
                        hp_dec, k1, k2, _ = read_xor_value(handle, candidate_base + 24)
                        maxhp_dec, _, _, _ = read_xor_value(handle, candidate_base + 40)
                        mp_dec, _, _, _ = read_xor_value(handle, candidate_base + 56)
                        maxmp_dec, _, _, _ = read_xor_value(handle, candidate_base + 72)
                        health = read_int(handle, candidate_base + 236)
                        gold = read_int(handle, candidate_base + 244)
                        level = read_int(handle, candidate_base + 4)
                        print(f"    偏移+4   level    = {level}")
                        print(f"    偏移+24  HP(解码) = {hp_dec}")
                        print(f"    偏移+40  MaxHP    = {maxhp_dec}")
                        print(f"    偏移+56  MP(解码) = {mp_dec}")
                        print(f"    偏移+72  MaxMP    = {maxmp_dec}")
                        print(f"    偏移+236 health   = {health}")
                        print(f"    偏移+244 gold     = {gold}")

                        looks_valid = (level is not None and 1 <= level <= 200
                                       and hp_dec is not None and 0 <= hp_dec <= 99999
                                       and maxhp_dec is not None and 0 < maxhp_dec <= 99999
                                       and health is not None and 0 <= health <= 100)
                        if looks_valid:
                            print(f"    >>> 数据看起来合理！playerbase 地址可能是: 0x{candidate_base:X}")

                            print(f"\n    --- 尝试读取物品栏 (偏移+412) ---")
                            item_base = candidate_base + 412
                            ITEM_INFO_SIZE = 0x65C
                            for slot in range(8, 28):
                                item_addr = item_base + slot * ITEM_INFO_SIZE
                                valid = read_short(handle, item_addr)
                                if valid and valid != 0:
                                    item_name = read_string(handle, item_addr + 2, 46)
                                    item_count = read_int(handle, item_addr + 1604)
                                    item_id = read_int(handle, item_addr + 1600)
                                    print(f"    背包[{slot-8:>2}]: valid={valid}, id={item_id}, name='{item_name}', count={item_count}")
                                else:
                                    print(f"    背包[{slot-8:>2}]: (空)")
        else:
            print("  未找到角色名！可能原因：")
            print("    1. 角色名输入有误")
            print("    2. 游戏编码不是GBK")
            print("    3. 镜像大小估计不对，搜索范围不够")

    print("\n" + "=" * 65)
    print("  诊断完成")
    print("=" * 65)
    print("\n  请将以上输出发给我，我来分析正确的偏移量。")
    print("  特别关注：")
    print("    1. 哪个版本的偏移能读出正确的角色名")
    print("    2. 搜索结果中哪处地址的数据看起来合理")
    print("    3. HP/MP/等级等数值是否符合实际")

    CloseHandle(handle)
    input("\n按回车退出...")


if __name__ == "__main__":
    main()
