"""
CGAssistant 偏移搜索脚本
========================
用已知的游戏数值（等级、HP、MP等）在内存中搜索 playerbase 结构。

使用方法：
1. 以管理员身份打开 CMD
2. 运行: python search.py
3. 输入当前角色的精确数值
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

def hex_dump(data, base_addr):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"  {base_addr+i:08X}: {hex_part:<48s} {ascii_part}")
    return '\n'.join(lines)

def scan_int(handle, base_addr, image_size, target_value, max_results=50):
    target_bytes = struct.pack('<i', target_value)
    results = []
    chunk_size = 65536
    for offset in range(0, image_size, chunk_size):
        read_size = min(chunk_size + 4, image_size - offset)
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

def scan_xor_value(handle, base_addr, image_size, target_value, max_results=50):
    results = []
    chunk_size = 65536
    for offset in range(0, image_size - 16, chunk_size):
        read_size = min(chunk_size + 16, image_size - offset)
        data = read_mem(handle, base_addr + offset, read_size)
        if data is None:
            continue
        for i in range(0, len(data) - 12, 4):
            k1, k2 = struct.unpack('<ii', data[i:i+8])
            if (k1 ^ k2) == target_value and k1 != 0 and k2 != 0:
                addr = base_addr + offset + i
                results.append((addr, k1, k2))
                if len(results) >= max_results:
                    return results
    return results

def main():
    print("=" * 65)
    print("  CGAssistant 偏移搜索脚本")
    print("=" * 65)

    print("\n  请输入角色当前精确数值（必须和游戏中完全一致）：")
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
        print(f"  无法打开进程")
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

    # ==========================================
    # 策略1: 搜索 level 作为普通 int
    # ==========================================
    print(f"\n{'='*65}")
    print(f"  策略1: 搜索 level={level} 作为普通int (04 00 00 00)")
    print(f"{'='*65}")

    level_addrs = scan_int(handle, base_addr, image_size, level, max_results=100)
    print(f"  找到 {len(level_addrs)} 处")

    candidates = []

    for addr in level_addrs:
        if addr < base_addr or addr > base_addr + image_size:
            continue

        # 检查: 如果这是 playerbase_t 的 level 字段(偏移+4)
        # 那么 playerbase 起始地址 = addr - 4
        pb_addr = addr - 4

        race = read_short(handle, pb_addr)
        pad = read_short(handle, pb_addr + 2)
        lv = read_int(handle, pb_addr + 4)

        if race is None or lv != level:
            continue

        # 读取 XOR 编码的 HP/MP
        hp_dec = read_xor_value(handle, pb_addr + 24)
        maxhp_dec = read_xor_value(handle, pb_addr + 40)
        mp_dec = read_xor_value(handle, pb_addr + 56)
        maxmp_dec = read_xor_value(handle, pb_addr + 72)
        health = read_int(handle, pb_addr + 236)
        gold = read_int(handle, pb_addr + 244)
        name = read_string(handle, pb_addr + 256, 17)

        match_score = 0
        reasons = []

        if hp_dec == hp:
            match_score += 10
            reasons.append(f"HP={hp_dec}✓")
        elif hp_dec is not None and 0 < hp_dec < 99999:
            reasons.append(f"HP={hp_dec}?")

        if maxhp_dec == maxhp:
            match_score += 10
            reasons.append(f"MaxHP={maxhp_dec}✓")
        elif maxhp_dec is not None and 0 < maxhp_dec < 99999:
            reasons.append(f"MaxHP={maxhp_dec}?")

        if mp_dec == mp:
            match_score += 10
            reasons.append(f"MP={mp_dec}✓")
        elif mp_dec is not None and 0 < mp_dec < 99999:
            reasons.append(f"MP={mp_dec}?")

        if maxmp_dec == maxmp:
            match_score += 10
            reasons.append(f"MaxMP={maxmp_dec}✓")
        elif maxmp_dec is not None and 0 < maxmp_dec < 99999:
            reasons.append(f"MaxMP={maxmp_dec}?")

        if health is not None and 0 <= health <= 100:
            match_score += 2
            reasons.append(f"health={health}")

        if gold is not None and 0 <= gold < 99999999:
            match_score += 2
            reasons.append(f"gold={gold}")

        if name and len(name) > 0:
            match_score += 5
            reasons.append(f"name='{name}'")

        if match_score >= 10:
            print(f"\n  >>> 候选地址: playerbase = 0x{pb_addr:X} (得分={match_score})")
            print(f"      偏移 = 0x{pb_addr - base_addr:X}")
            print(f"      {', '.join(reasons)}")

            # 读取物品栏
            print(f"      --- 物品栏 ---")
            ITEM_INFO_SIZE = 0x65C
            for slot in range(8, 28):
                item_addr = pb_addr + 412 + slot * ITEM_INFO_SIZE
                valid = read_short(handle, item_addr)
                if valid and valid != 0:
                    item_name = read_string(handle, item_addr + 2, 46)
                    item_count = read_int(handle, item_addr + 1604)
                    print(f"      背包[{slot-8:>2}]: name='{item_name}', count={item_count}")
                else:
                    print(f"      背包[{slot-8:>2}]: (空)")

            candidates.append((pb_addr, match_score))

        # 也检查: level 可能在偏移+4但 race 是 short
        # 尝试 pb_addr = addr - 4 + 不同的 name 偏移
        # 有些版本 name 偏移可能不同

    # ==========================================
    # 策略2: 搜索 XOR 编码的 HP 值
    # ==========================================
    print(f"\n{'='*65}")
    print(f"  策略2: 搜索 XOR 编码的 HP={hp}")
    print(f"{'='*65}")

    hp_xor_results = scan_xor_value(handle, base_addr, image_size, hp, max_results=30)
    print(f"  找到 {len(hp_xor_results)} 处 XOR 对 (key1^key2={hp})")

    for addr, k1, k2 in hp_xor_results:
        # 如果这是 playerbase_t 的 hp 字段(偏移+24)
        pb_addr = addr - 24

        race = read_short(handle, pb_addr)
        lv = read_int(handle, pb_addr + 4)

        hp_dec = read_xor_value(handle, pb_addr + 24)
        maxhp_dec = read_xor_value(handle, pb_addr + 40)
        mp_dec = read_xor_value(handle, pb_addr + 56)
        maxmp_dec = read_xor_value(handle, pb_addr + 72)
        health = read_int(handle, pb_addr + 236)
        name = read_string(handle, pb_addr + 256, 17)

        match_score = 0
        reasons = []

        if lv == level:
            match_score += 5
            reasons.append(f"level={lv}✓")
        else:
            reasons.append(f"level={lv}?")

        if hp_dec == hp:
            match_score += 10
            reasons.append(f"HP={hp_dec}✓")
        if maxhp_dec == maxhp:
            match_score += 10
            reasons.append(f"MaxHP={maxhp_dec}✓")
        if mp_dec == mp:
            match_score += 10
            reasons.append(f"MP={mp_dec}✓")
        if maxmp_dec == maxmp:
            match_score += 10
            reasons.append(f"MaxMP={maxmp_dec}✓")
        if health is not None and 0 <= health <= 100:
            match_score += 2
            reasons.append(f"health={health}")
        if name and len(name) > 0:
            match_score += 5
            reasons.append(f"name='{name}'")

        if match_score >= 15:
            print(f"\n  >>> 候选地址: playerbase = 0x{pb_addr:X} (得分={match_score})")
            print(f"      偏移 = 0x{pb_addr - base_addr:X}")
            print(f"      {', '.join(reasons)}")

            print(f"      --- 物品栏 ---")
            ITEM_INFO_SIZE = 0x65C
            for slot in range(8, 28):
                item_addr = pb_addr + 412 + slot * ITEM_INFO_SIZE
                valid = read_short(handle, item_addr)
                if valid and valid != 0:
                    item_name = read_string(handle, item_addr + 2, 46)
                    item_count = read_int(handle, item_addr + 1604)
                    print(f"      背包[{slot-8:>2}]: name='{item_name}', count={item_count}")
                else:
                    print(f"      背包[{slot-8:>2}]: (空)")

            candidates.append((pb_addr, match_score))

        # 也检查: HP XOR 可能在偏移+24，但 playerbase 是指针
        # 尝试: 这里的 HP 可能属于 playerbase 指向的结构
        # 所以需要检查 addr - 24 是否是一个合理的结构起始

    # ==========================================
    # 策略3: 搜索 MaxHP XOR 值
    # ==========================================
    if maxhp > 0 and maxhp != hp:
        print(f"\n{'='*65}")
        print(f"  策略3: 搜索 XOR 编码的 MaxHP={maxhp}")
        print(f"{'='*65}")

        maxhp_xor_results = scan_xor_value(handle, base_addr, image_size, maxhp, max_results=30)
        print(f"  找到 {len(maxhp_xor_results)} 处")

        # 检查 HP XOR 是否在 -16 偏移处
        for addr, k1, k2 in maxhp_xor_results:
            hp_at_minus16 = read_xor_value(handle, addr - 16)
            if hp_at_minus16 == hp:
                pb_addr = addr - 40
                lv = read_int(handle, pb_addr + 4)
                mp_dec = read_xor_value(handle, pb_addr + 56)
                maxmp_dec = read_xor_value(handle, pb_addr + 72)
                name = read_string(handle, pb_addr + 256, 17)

                match_score = 0
                reasons = [f"HP={hp_at_minus16}✓", f"MaxHP={maxhp}✓"]

                if lv == level:
                    match_score += 5
                    reasons.append(f"level={lv}✓")
                if mp_dec == mp:
                    match_score += 10
                    reasons.append(f"MP={mp_dec}✓")
                if maxmp_dec == maxmp:
                    match_score += 10
                    reasons.append(f"MaxMP={maxmp_dec}✓")
                if name and len(name) > 0:
                    match_score += 5
                    reasons.append(f"name='{name}'")

                match_score += 20  # HP and MaxHP both match

                print(f"\n  >>> 候选地址: playerbase = 0x{pb_addr:X} (得分={match_score})")
                print(f"      偏移 = 0x{pb_addr - base_addr:X}")
                print(f"      {', '.join(reasons)}")

                if lv == level and mp_dec == mp:
                    print(f"      --- 物品栏 ---")
                    ITEM_INFO_SIZE = 0x65C
                    for slot in range(8, 28):
                        item_addr = pb_addr + 412 + slot * ITEM_INFO_SIZE
                        valid = read_short(handle, item_addr)
                        if valid and valid != 0:
                            item_name = read_string(handle, item_addr + 2, 46)
                            item_count = read_int(handle, item_addr + 1604)
                            print(f"      背包[{slot-8:>2}]: name='{item_name}', count={item_count}")
                        else:
                            print(f"      背包[{slot-8:>2}]: (空)")

                candidates.append((pb_addr, match_score))

    # ==========================================
    # 策略4: 在角色名附近搜索 level
    # ==========================================
    if player_name:
        print(f"\n{'='*65}")
        print(f"  策略4: 在角色名 '{player_name}' 附近搜索 level={level}")
        print(f"{'='*65}")

        name_bytes = player_name.encode('gbk')
        chunk_size = 65536
        name_locations = []

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
                name_locations.append(base_addr + offset + idx)
                pos = idx + 1

        print(f"  角色名出现 {len(name_locations)} 处")

        level_bytes = struct.pack('<i', level)

        for name_addr in name_locations:
            # 在名字前后 0x400 字节范围内搜索 level
            search_start = max(base_addr, name_addr - 0x400)
            search_end = min(base_addr + image_size, name_addr + 0x400)
            search_data = read_mem(handle, search_start, search_end - search_start)
            if search_data is None:
                continue

            pos = 0
            while True:
                idx = search_data.find(level_bytes, pos)
                if idx == -1:
                    break
                level_addr = search_start + idx
                pb_addr = level_addr - 4

                race = read_short(handle, pb_addr)
                hp_dec = read_xor_value(handle, pb_addr + 24)
                maxhp_dec = read_xor_value(handle, pb_addr + 40)
                mp_dec = read_xor_value(handle, pb_addr + 56)
                maxmp_dec = read_xor_value(handle, pb_addr + 72)

                if hp_dec == hp and maxhp_dec == maxhp:
                    health = read_int(handle, pb_addr + 236)
                    gold = read_int(handle, pb_addr + 244)
                    name_at_256 = read_string(handle, pb_addr + 256, 17)

                    print(f"\n  >>>>>> 高置信度匹配! playerbase = 0x{pb_addr:X} <<<<<<")
                    print(f"        偏移 = 0x{pb_addr - base_addr:X}")
                    print(f"        race={race}, level={level}")
                    print(f"        HP={hp_dec}/{maxhp_dec}, MP={mp_dec}/{maxmp_dec}")
                    print(f"        health={health}, gold={gold}")
                    print(f"        name(+256)='{name_at_256}'")
                    print(f"        name_addr=0x{name_addr:X}, name_offset_in_struct=0x{name_addr - pb_addr:X}")

                    print(f"        --- 物品栏 ---")
                    ITEM_INFO_SIZE = 0x65C
                    for slot in range(8, 28):
                        item_addr = pb_addr + 412 + slot * ITEM_INFO_SIZE
                        valid = read_short(handle, item_addr)
                        if valid and valid != 0:
                            item_name = read_string(handle, item_addr + 2, 46)
                            item_count = read_int(handle, item_addr + 1604)
                            print(f"        背包[{slot-8:>2}]: name='{item_name}', count={item_count}")
                        else:
                            print(f"        背包[{slot-8:>2}]: (空)")

                    candidates.append((pb_addr, 100))

                pos = idx + 1

    # ==========================================
    # 汇总
    # ==========================================
    print(f"\n{'='*65}")
    print(f"  搜索完成 - 汇总")
    print(f"{'='*65}")

    if candidates:
        candidates.sort(key=lambda x: -x[1])
        seen = set()
        for pb_addr, score in candidates:
            if pb_addr in seen:
                continue
            seen.add(pb_addr)
            offset = pb_addr - base_addr
            print(f"  playerbase=0x{pb_addr:X}  偏移=0x{offset:X}  得分={score}")
    else:
        print("  未找到匹配的 playerbase 地址")
        print("  可能原因：")
        print("    1. 输入的数值和游戏中不完全一致")
        print("    2. 游戏版本结构布局与源码不同")
        print("    3. playerbase 是通过指针间接访问的")

        # 最后尝试: 搜索指针指向 playerbase
        print(f"\n  尝试: 在镜像中搜索指向角色名附近的指针...")

        if name_locations:
            for name_addr in name_locations[:3]:
                # 搜索指向 name_addr - 256 的指针
                target_ptr = name_addr - 256
                ptr_bytes = struct.pack('<I', target_ptr)
                ptr_results = []
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
                        ptr_results.append(base_addr + offset + idx)
                        pos = idx + 1
                        if len(ptr_results) >= 10:
                            break
                    if len(ptr_results) >= 10:
                        break

                if ptr_results:
                    print(f"\n  角色名在 0x{name_addr:X}, 搜索指向 0x{target_ptr:X} 的指针:")
                    for pa in ptr_results:
                        print(f"    指针地址: 0x{pa:X} (偏移 0x{pa - base_addr:X})")

    CloseHandle(handle)
    input("\n按回车退出...")


if __name__ == "__main__":
    main()
