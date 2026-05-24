"""
CGAssistant 全内存搜索脚本
==========================
在进程的整个可读内存中搜索 HP/MP 值。

使用方法：
1. 以管理员身份打开 CMD
2. 运行: python memscan.py
"""

import ctypes
import ctypes.wintypes as wintypes
import struct
import os

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_READONLY = 0x02
PAGE_EXECUTE_READ = 0x20

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]
class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]
class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE
CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL
ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL
VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
VirtualQueryEx.restype = ctypes.c_size_t
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
EnumProcessModules = psapi.EnumProcessModules
EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
EnumProcessModules.restype = wintypes.BOOL

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

def is_readable(protect):
    return protect in (PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
                       PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)

def main():
    print("=" * 65)
    print("  CGAssistant 全内存搜索脚本")
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

    # ==========================================
    # 第一步: 扫描所有可读内存区域
    # ==========================================
    print(f"\n  扫描进程内存区域...")

    regions = []
    addr = 0x10000
    max_addr = 0x7FFFFFFF

    while addr < max_addr:
        mbi = MEMORY_BASIC_INFORMATION()
        result = VirtualQueryEx(handle, addr, ctypes.byref(mbi), ctypes.sizeof(mbi))
        if result == 0:
            break
        base = mbi.BaseAddress if mbi.BaseAddress is not None else addr
        size = mbi.RegionSize
        if mbi.State == MEM_COMMIT and is_readable(mbi.Protect):
            regions.append((base, size))
        if size == 0:
            break
        addr = base + size

    total_size = sum(s for _, s in regions)
    print(f"  找到 {len(regions)} 个可读区域, 总大小: {total_size // 1024 // 1024}MB")

    # ==========================================
    # 第二步: 在所有内存中搜索 HP 值
    # ==========================================
    # 策略: 搜索 HP 作为普通int, 然后检查附近是否有 MaxHP, MP, MaxMP
    # 这样可以大幅减少误报

    hp_bytes = struct.pack('<i', hp)
    maxhp_bytes = struct.pack('<i', maxhp)

    # 也搜索 short 格式
    hp_short_bytes = struct.pack('<h', hp)
    maxhp_short_bytes = struct.pack('<h', maxhp)

    candidates = []

    print(f"\n  搜索 HP={hp} (普通int) 在附近有 MaxHP={maxhp} 的位置...")

    scanned = 0
    for base, size in regions:
        scanned += size
        if scanned % (50 * 1024 * 1024) < size:
            print(f"  已扫描 {scanned // 1024 // 1024}MB / {total_size // 1024 // 1024}MB...")

        data = read_mem(handle, base, size)
        if data is None:
            continue

        # 搜索 int 格式: HP 后面 4-16 字节内跟着 MaxHP
        pos = 0
        while True:
            idx = data.find(hp_bytes, pos)
            if idx == -1:
                break

            # 检查 +4 到 +20 范围内是否有 MaxHP
            for offset in range(4, 24, 4):
                check_pos = idx + offset
                if check_pos + 4 <= len(data):
                    val = struct.unpack('<i', data[check_pos:check_pos+4])[0]
                    if val == maxhp:
                        abs_addr = base + idx
                        # 进一步检查 MP 和 MaxMP
                        mp_found = False
                        maxmp_found = False
                        mp_offset = None

                        for mp_off in range(offset + 4, offset + 80, 4):
                            if check_pos + mp_off - offset + 4 <= len(data):
                                val2 = struct.unpack('<i', data[idx + mp_off:idx + mp_off + 4])[0]
                                if val2 == mp and not mp_found:
                                    mp_found = True
                                    mp_offset = mp_off
                                elif val2 == maxmp and mp_found:
                                    maxmp_found = True
                                    break

                        if mp_found and maxmp_found:
                            candidates.append(('int', abs_addr, idx, data[max(0,idx-64):min(len(data),idx+128)]))
                        elif mp_found:
                            candidates.append(('int_partial', abs_addr, idx, data[max(0,idx-64):min(len(data),idx+128)]))
                        elif maxhp == hp:
                            candidates.append(('int_hpmaxhp_same', abs_addr, idx, data[max(0,idx-64):min(len(data),idx+128)]))

            pos = idx + 1

    # 搜索 short 格式
    print(f"\n  搜索 HP={hp} (short) 在附近有 MaxHP={maxhp} 的位置...")

    for base, size in regions:
        data = read_mem(handle, base, size)
        if data is None:
            continue

        pos = 0
        while True:
            idx = data.find(hp_short_bytes, pos)
            if idx == -1:
                break
            if idx % 2 != 0:
                pos = idx + 1
                continue

            for offset in range(2, 16, 2):
                check_pos = idx + offset
                if check_pos + 2 <= len(data):
                    val = struct.unpack('<h', data[check_pos:check_pos+2])[0]
                    if val == maxhp:
                        abs_addr = base + idx
                        mp_found = False
                        maxmp_found = False
                        for mp_off in range(offset + 2, offset + 40, 2):
                            if idx + mp_off + 2 <= len(data):
                                val2 = struct.unpack('<h', data[idx + mp_off:idx + mp_off + 2])[0]
                                if val2 == mp and not mp_found:
                                    mp_found = True
                                elif val2 == maxmp and mp_found:
                                    maxmp_found = True
                                    break

                        if mp_found and maxmp_found:
                            candidates.append(('short', abs_addr, idx, data[max(0,idx-64):min(len(data),idx+128)]))

            pos = idx + 1

    # 搜索 XOR 格式
    print(f"\n  搜索 HP={hp} (XOR编码) 在附近有 MaxHP={maxhp} 的位置...")

    for base, size in regions:
        data = read_mem(handle, base, size)
        if data is None:
            continue

        for i in range(0, len(data) - 28, 4):
            k1, k2 = struct.unpack('<ii', data[i:i+8])
            if (k1 ^ k2) == hp and k1 != 0 and k2 != 0:
                for off in range(8, 40, 4):
                    if i + off + 8 <= len(data):
                        k3, k4 = struct.unpack('<ii', data[i+off:i+off+8])
                        if (k3 ^ k4) == maxhp and k3 != 0 and k4 != 0:
                            abs_addr = base + i
                            mp_found = False
                            maxmp_found = False
                            for mp_off in range(off + 8, off + 80, 4):
                                if i + mp_off + 8 <= len(data):
                                    k5, k6 = struct.unpack('<ii', data[i+mp_off:i+mp_off+8])
                                    decoded = k5 ^ k6
                                    if decoded == mp and not mp_found:
                                        mp_found = True
                                    elif decoded == maxmp and mp_found:
                                        maxmp_found = True
                                        break

                            if mp_found and maxmp_found:
                                candidates.append(('xor', abs_addr, i, data[max(0,i-64):min(len(data),i+128)]))
                            break

    # ==========================================
    # 第三步: 输出结果
    # ==========================================
    print(f"\n{'='*65}")
    print(f"  搜索结果: 找到 {len(candidates)} 个候选")
    print(f"{'='*65}")

    for ctype, abs_addr, _, chunk in candidates:
        print(f"\n  类型: {ctype}, 地址: 0x{abs_addr:X}")
        print(f"  --- 周围数据 (前64字节 + 后128字节) ---")

        for i in range(0, len(chunk), 16):
            line = chunk[i:i+16]
            hex_part = ' '.join(f'{b:02X}' for b in line)

            ints = []
            for k in range(0, min(16, len(line)), 4):
                if k + 4 <= len(line):
                    iv = struct.unpack('<i', line[k:k+4])[0]
                    label = ""
                    if iv == level: label = " <<<level>>>"
                    elif iv == hp: label = " <<<HP>>>"
                    elif iv == maxhp: label = " <<<MaxHP>>>"
                    elif iv == mp: label = " <<<MP>>>"
                    elif iv == maxmp: label = " <<<MaxMP>>>"
                    ints.append(f"{iv}{label}")

            shorts = []
            for k in range(0, min(16, len(line)), 2):
                if k + 2 <= len(line):
                    sv = struct.unpack('<h', line[k:k+2])[0]
                    if sv == hp: shorts.append(f"+{i+k}:HP(short)")
                    elif sv == maxhp: shorts.append(f"+{i+k}:MaxHP(short)")
                    elif sv == mp: shorts.append(f"+{i+k}:MP(short)")
                    elif sv == maxmp: shorts.append(f"+{i+k}:MaxMP(short)")

            ints_str = ' | '.join(ints)
            rel = i - 64
            print(f"  {abs_addr + rel:+8X} ({rel:+5d}): {hex_part}")
            print(f"    ints: {ints_str}")
            if shorts:
                print(f"    shorts: {', '.join(shorts)}")

        # 尝试以 HP 地址为锚点，搜索名字
        if ctype == 'int':
            for name_search_start in range(-0x400, 0, 4):
                name_addr = abs_addr + name_search_start
                name_val = read_string(handle, name_addr, 32)
                if name_val == player_name:
                    print(f"\n  >>> 名字 '{player_name}' 在 HP 前 {name_search_start} 字节处 (偏移 0x{abs(name_search_start):X})")
                    print(f"  >>> 这意味着 playerbase 起始地址可能在 0x{name_addr:X}")

        # 搜索指向此区域的指针
        print(f"\n  --- 搜索指向 0x{abs_addr:X} 附近的全局指针 ---")
        for search_offset in range(0, 0x20, 4):
            target = abs_addr + search_offset - 0x40
            ptr_bytes = struct.pack('<I', target)
            hModules = (wintypes.HMODULE * 1024)()
            cbNeeded = wintypes.DWORD()
            if EnumProcessModules(handle, hModules, ctypes.sizeof(hModules), ctypes.byref(cbNeeded)):
                base_addr = hModules[0]
                mi = MEMORY_BASIC_INFORMATION()
                # 只搜索镜像范围
                for scan_off in range(0, 0x1100000, 65536):
                    d = read_mem(handle, base_addr + scan_off, 65536)
                    if d is None:
                        continue
                    p = 0
                    while True:
                        fi = d.find(ptr_bytes, p)
                        if fi == -1:
                            break
                        ptr_addr = base_addr + scan_off + fi
                        ptr_off = ptr_addr - base_addr
                        print(f"    0x{ptr_addr:X} (偏移 0x{ptr_off:X}) -> 0x{target:X}")
                        p = fi + 1
                        if p > 5:
                            break

    # 如果没找到任何候选，尝试更宽松的搜索
    if not candidates:
        print(f"\n  未找到 HP+MaxHP+MP+MaxMP 组合")
        print(f"  尝试仅搜索 MaxMP={maxmp} (最独特的值)...")

        maxmp_bytes = struct.pack('<i', maxmp)
        maxmp_locs = []

        for base, size in regions:
            data = read_mem(handle, base, size)
            if data is None:
                continue
            pos = 0
            count = 0
            while count < 30:
                idx = data.find(maxmp_bytes, pos)
                if idx == -1:
                    break
                abs_addr = base + idx
                maxmp_locs.append(abs_addr)
                pos = idx + 1
                count += 1

        print(f"  找到 {len(maxmp_locs)} 处 MaxMP={maxmp}")

        for addr in maxmp_locs:
            # dump 周围数据
            chunk = read_mem(handle, max(0, addr - 64), 192)
            if chunk is None:
                continue

            print(f"\n  MaxMP={maxmp} 在 0x{addr:X}:")
            for i in range(0, len(chunk), 16):
                line = chunk[i:i+16]
                hex_part = ' '.join(f'{b:02X}' for b in line)
                ints = []
                for k in range(0, min(16, len(line)), 4):
                    if k + 4 <= len(line):
                        iv = struct.unpack('<i', line[k:k+4])[0]
                        label = ""
                        if iv == level: label = " <<<level>>>"
                        elif iv == hp: label = " <<<HP>>>"
                        elif iv == maxhp: label = " <<<MaxHP>>>"
                        elif iv == mp: label = " <<<MP>>>"
                        elif iv == maxmp: label = " <<<MaxMP>>>"
                        ints.append(f"{iv}{label}")
                ints_str = ' | '.join(ints)
                rel = i - 64
                print(f"  {addr + rel:+8X} ({rel:+5d}): {hex_part}")
                print(f"    ints: {ints_str}")

    CloseHandle(handle)
    input("\n按回车退出...")


if __name__ == "__main__":
    main()
