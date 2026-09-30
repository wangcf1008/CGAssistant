"""
CGAssistant 交互式内存搜索器
============================
类似金山游侠/Cheat Engine的工作方式：
1. 首次搜索：在整个进程内存中搜索一个值
2. 再次搜索：在已找到的地址中搜索新值（缩小范围）
3. 支持保存/加载搜索结果

使用方法：
1. 以管理员身份打开 CMD
2. 运行: python scanner.py
3. 按菜单提示操作

典型工作流程：
  a) 记下当前HP（比如129）
  b) 首次搜索 129
  c) 在游戏中改变HP（比如吃药到满血，或被攻击）
  d) 记下新HP（比如150）
  e) 再次搜索 150
  f) 重复直到只剩1-2个地址
  g) 用"查看"命令确认正确地址
  h) 用菜单 10 "指针扫描" 把该(堆)地址变成稳定的 基址+偏移
  i) 重启游戏后用菜单 11 验证，能读出正确值的那条链即可写进读取脚本

为什么需要菜单10：直接搜到的地址在堆里，每次重启游戏都会变。
而"EXE主模块内的全局指针 + 偏移"每次启动位置固定，才是可长期使用的读取路径。
"""

import ctypes
import ctypes.wintypes as wintypes
import struct
import os
import json
import time

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

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
EnumProcessModules = ctypes.windll.psapi.EnumProcessModules
EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
EnumProcessModules.restype = wintypes.BOOL

SAVE_FILE = "scan_results.json"

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

def is_readable(protect):
    return protect in (PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
                       PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)

def get_memory_regions(handle):
    regions = []
    addr = 0x10000
    while addr < 0x7FFFFFFF:
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
    return regions

def first_scan(handle, value, data_type='int'):
    results = []
    regions = get_memory_regions(handle)
    total = sum(s for _, s in regions)
    scanned = 0

    if data_type == 'int':
        target = struct.pack('<i', value)
    elif data_type == 'short':
        target = struct.pack('<h', value)
    elif data_type == 'xor':
        pass

    for base, size in regions:
        scanned += size
        pct = scanned * 100 // total
        print(f"\r  扫描进度: {pct}% ({scanned // 1024 // 1024}MB / {total // 1024 // 1024}MB)  找到: {len(results)}", end='', flush=True)

        data = read_mem(handle, base, size)
        if data is None:
            continue

        if data_type == 'xor':
            for i in range(0, len(data) - 12, 4):
                k1, k2 = struct.unpack('<ii', data[i:i+8])
                if (k1 ^ k2) == value and k1 != 0 and k2 != 0:
                    results.append(base + i)
        else:
            pos = 0
            while True:
                idx = data.find(target, pos)
                if idx == -1:
                    break
                if data_type == 'short' and idx % 2 != 0:
                    pos = idx + 1
                    continue
                results.append(base + idx)
                pos = idx + 1

    print(f"\r  扫描完成: 找到 {len(results)} 个地址                    ")
    return results

def next_scan(handle, prev_addrs, value, data_type='int'):
    results = []

    for addr in prev_addrs:
        if data_type == 'int':
            v = read_int(handle, addr)
            if v is not None and v == value:
                results.append(addr)
        elif data_type == 'short':
            v = read_short(handle, addr)
            if v is not None and v == value:
                results.append(addr)
        elif data_type == 'xor':
            data = read_mem(handle, addr, 16)
            if data and len(data) >= 12:
                k1, k2 = struct.unpack('<ii', data[:8])
                if (k1 ^ k2) == value and k1 != 0 and k2 != 0:
                    results.append(addr)

    print(f"  过滤完成: {len(prev_addrs)} -> {len(results)} 个地址")
    return results

def next_scan_changed(handle, prev_addrs):
    results = []
    for addr in prev_addrs:
        data = read_mem(handle, addr, 4)
        if data is not None and len(data) >= 4:
            results.append(addr)
    print(f"  过滤完成: {len(prev_addrs)} -> {len(results)} 个地址 (有效地址)")
    return results

def next_scan_unchanged(handle, prev_addrs, prev_values):
    results = []
    for i, addr in enumerate(prev_addrs):
        if i >= len(prev_values):
            break
        data = read_mem(handle, addr, 4)
        if data is not None and len(data) >= 4:
            cur = struct.unpack('<i', data[:4])[0]
            if cur == prev_values[i]:
                results.append(addr)
    print(f"  过滤完成: {len(prev_addrs)} -> {len(results)} 个地址 (未变化)")
    return results

def dump_address(handle, addr, size=256):
    data = read_mem(handle, max(0, addr - size // 2), size)
    if data is None:
        print("  无法读取")
        return

    start = max(0, addr - size // 2)
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        abs_addr = start + i

        ints = []
        for k in range(0, min(16, len(chunk)), 4):
            if k + 4 <= len(chunk):
                iv = struct.unpack('<i', chunk[k:k+4])[0]
                ints.append(str(iv))

        shorts = []
        for k in range(0, min(16, len(chunk)), 2):
            if k + 2 <= len(chunk):
                sv = struct.unpack('<h', chunk[k:k+2])[0]
                shorts.append(str(sv))

        marker = " <<<" if abs_addr == addr else ""
        print(f"  0x{abs_addr:08X}: {hex_part}  [{', '.join(ints)}]{marker}")

def save_results(addrs, values, data_type, label):
    data = {
        'label': label,
        'data_type': data_type,
        'addresses': addrs,
        'values': values,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'count': len(addrs),
    }
    with open(SAVE_FILE, 'w') as f:
        json.dump(data, f)
    print(f"  已保存到 {SAVE_FILE}")

def load_results():
    if not os.path.exists(SAVE_FILE):
        print(f"  文件 {SAVE_FILE} 不存在")
        return None, None, None, None
    with open(SAVE_FILE, 'r') as f:
        data = json.load(f)
    print(f"  已加载: {data.get('label', '')} ({data['count']}个地址, {data.get('timestamp', '')})")
    return data['addresses'], data.get('values', []), data['data_type'], data.get('label', '')

# =============================================
# 指针扫描：把易变的堆地址变成稳定的"基址+偏移"
# =============================================
POINTER_FILE = "pointer_results.json"

def get_module_regions(handle, module_base):
    """枚举游戏主模块(EXE)自身占用的可读内存区域。
    全局指针(如 g_playerBase)就存放在这些区域里，地址每次启动都固定。"""
    regions = []
    addr = module_base
    while addr < module_base + 0x4000000:
        mbi = MEMORY_BASIC_INFORMATION()
        if VirtualQueryEx(handle, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        base = mbi.BaseAddress if mbi.BaseAddress is not None else addr
        if mbi.AllocationBase is not None and mbi.AllocationBase != module_base:
            break
        if mbi.State == MEM_COMMIT and is_readable(mbi.Protect):
            regions.append((base, mbi.RegionSize))
        if mbi.RegionSize == 0:
            break
        addr = base + mbi.RegionSize
    return regions

def find_pointer_hits(handle, regions, target, max_offset, min_val=0x10000, limit=100000):
    """在给定区域内查找所有满足 p + off == target 的4字节指针 p。
    返回 [(指针所在地址, p的值, off)]。"""
    lo = target - max_offset
    hits = []
    for base, size in regions:
        data = read_mem(handle, base, size)
        if data is None:
            continue
        n = len(data) - (len(data) % 4)
        for idx, (v,) in enumerate(struct.iter_unpack('<I', data[:n])):
            if lo <= v <= target and v >= min_val:
                hits.append((base + idx * 4, v, target - v))
                if len(hits) >= limit:
                    return hits
    return hits

def in_regions(addr, regions):
    for b, s in regions:
        if b <= addr < b + s:
            return True
    return False

def pointer_scan(handle, module_regions, all_regions, target, max_offset, max_level):
    """多级指针扫描，从目标值向上(朝基址方向)逐级回溯。

    每一级都在全部内存中查找"指向上一级地址"的指针：
      - 若指针本身位于EXE主模块内，说明它是全局变量，地址每次启动都固定，
        这就是我们要的'稳定根'，记入结果。
      - 若指针位于堆中，则它不稳定，继续向上回溯(若还没到最大层级)。
    返回 [(基址, [偏移1, 偏移2, ...])]，读取语义见 read_chain。
    """
    results = []
    frontier = [(target, [])]
    for level in range(1, max_level + 1):
        new_frontier = []
        for tgt, tail in frontier:
            hits = find_pointer_hits(handle, all_regions, tgt, max_offset)
            print(f"    第 {level} 级: 指向 0x{tgt:08X} 的候选指针 {len(hits)} 个")
            for addr, p, off in hits:
                chain = [off] + tail
                if in_regions(addr, module_regions):
                    results.append((addr, chain))          # 稳定根(在EXE内)
                elif level < max_level:
                    new_frontier.append((addr, chain))     # 堆内指针，继续回溯
                if len(results) + len(new_frontier) >= 20000:
                    print("    候选过多，已截断。请缩小偏移范围或降低层级。")
                    return results
        frontier = new_frontier
        if not frontier:
            break
    return results

def read_chain(handle, base_addr, offsets):
    """按指针链读取：返回 (最终地址, 值)。失败返回 (None, None)。"""
    p = read_int(handle, base_addr)
    if p is None or p < 0x10000:
        return None, None
    cur = p
    for i, off in enumerate(offsets):
        cur = cur + off
        if i != len(offsets) - 1:
            p = read_int(handle, cur)
            if p is None or p < 0x10000:
                return None, None
            cur = p
    return cur, read_int(handle, cur)

def save_pointer_results(results, base_addr, target, label):
    data = {
        'label': label,
        'target': target,
        'module_base': base_addr,
        'chains': [{'base': b, 'base_offset': b - base_addr, 'offsets': o} for b, o in results],
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
    }
    with open(POINTER_FILE, 'w') as f:
        json.dump(data, f)
    print(f"  已保存 {len(results)} 条指针链到 {POINTER_FILE}")

def load_pointer_results():
    if not os.path.exists(POINTER_FILE):
        print(f"  文件 {POINTER_FILE} 不存在")
        return None
    with open(POINTER_FILE, 'r') as f:
        return json.load(f)

def main():
    print("=" * 65)
    print("  CGAssistant 交互式内存搜索器")
    print("=" * 65)

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
    if EnumProcessModules(handle, hModules, ctypes.sizeof(hModules), ctypes.byref(cbNeeded)):
        base_addr = hModules[0]

    print(f"  游戏进程 PID={pid}, 基址=0x{base_addr:X}")

    module_regions = get_module_regions(handle, base_addr)
    mod_size = sum(s for _, s in module_regions)
    print(f"  主模块可读区域: {len(module_regions)} 段, 共 {mod_size // 1024} KB (全局指针扫描范围)")
    all_regions = get_memory_regions(handle)

    current_addrs = []
    current_values = []
    current_type = 'int'
    current_label = ''

    while True:
        print(f"\n{'='*65}")
        print(f"  当前状态: {len(current_addrs)} 个地址 | 类型: {current_type} | 标签: {current_label or '(无)'}")
        print(f"{'='*65}")
        print(f"  1. 首次搜索 (全内存扫描)")
        print(f"  2. 再次搜索 (在已有结果中过滤)")
        print(f"  3. 搜索[未变化] (值没变的地址)")
        print(f"  4. 搜索[已变化] (值变了的地址)")
        print(f"  5. 查看当前结果")
        print(f"  6. 查看指定地址详情")
        print(f"  7. 保存结果")
        print(f"  8. 加载结果")
        print(f"  9. 读取地址的当前值 (int/short/string)")
        print(f"  10. 指针扫描 (把易变堆地址变成稳定的 基址+偏移)")
        print(f"  11. 验证指针链 (游戏重启后确认是否依然有效)")
        print(f"  0. 退出")

        choice = input("\n  请选择: ").strip()

        if choice == '1':
            print("\n  数据类型:")
            print("    1. int (4字节, 最常见)")
            print("    2. short (2字节)")
            print("    3. XOR (异或加密, 8字节key1+key2)")
            type_choice = input("  选择类型 (1/2/3): ").strip()
            if type_choice == '2':
                current_type = 'short'
            elif type_choice == '3':
                current_type = 'xor'
            else:
                current_type = 'int'

            val_str = input(f"  输入要搜索的值 ({current_type}): ").strip()
            try:
                val = int(val_str)
            except ValueError:
                print("  无效数值")
                continue

            current_label = input("  输入标签 (如HP/MP/等级, 回车跳过): ").strip()
            print()

            current_addrs = first_scan(handle, val, current_type)
            current_values = [val] * len(current_addrs)

            if len(current_addrs) <= 50:
                print(f"\n  所有结果:")
                for addr in current_addrs:
                    offset = addr - base_addr
                    print(f"    0x{addr:08X} (偏移 0x{offset:X})")

        elif choice == '2':
            if not current_addrs:
                print("  请先执行首次搜索!")
                continue

            val_str = input(f"  输入新值 ({current_type}): ").strip()
            try:
                val = int(val_str)
            except ValueError:
                print("  无效数值")
                continue

            current_addrs = next_scan(handle, current_addrs, val, current_type)
            current_values = [val] * len(current_addrs)

            if len(current_addrs) <= 50:
                print(f"\n  所有结果:")
                for addr in current_addrs:
                    offset = addr - base_addr
                    print(f"    0x{addr:08X} (偏移 0x{offset:X})")

        elif choice == '3':
            if not current_addrs:
                print("  请先执行首次搜索!")
                continue
            current_addrs = next_scan_unchanged(handle, current_addrs, current_values)
            current_values = []
            for addr in current_addrs:
                v = read_int(handle, addr)
                current_values.append(v if v is not None else 0)

        elif choice == '4':
            if not current_addrs:
                print("  请先执行首次搜索!")
                continue
            new_addrs = []
            new_values = []
            for i, addr in enumerate(current_addrs):
                v = read_int(handle, addr)
                if v is not None and (i >= len(current_values) or v != current_values[i]):
                    new_addrs.append(addr)
                    new_values.append(v)
            current_addrs = new_addrs
            current_values = new_values
            print(f"  过滤完成: {len(current_addrs)} 个地址 (已变化)")

        elif choice == '5':
            if not current_addrs:
                print("  没有结果")
                continue

            page = 0
            page_size = 20
            while True:
                start = page * page_size
                end = min(start + page_size, len(current_addrs))
                print(f"\n  结果 {start+1}-{end} / {len(current_addrs)} (页 {page+1}):")
                for i in range(start, end):
                    addr = current_addrs[i]
                    offset = addr - base_addr
                    v = read_int(handle, addr)
                    v_str = str(v) if v is not None else "?"
                    print(f"    [{i}] 0x{addr:08X} (偏移 0x{offset:X}) 当前值={v_str}")

                if end >= len(current_addrs):
                    break
                more = input("  下一页? (y/n): ").strip().lower()
                if more != 'y':
                    break
                page += 1

        elif choice == '6':
            addr_str = input("  输入地址 (十六进制, 如 ED4028): ").strip()
            try:
                addr = int(addr_str, 16)
            except ValueError:
                print("  无效地址")
                continue

            size_str = input("  显示范围 (字节, 默认256): ").strip()
            size = int(size_str) if size_str else 256

            dump_address(handle, addr, size)

        elif choice == '7':
            if not current_addrs:
                print("  没有结果可保存")
                continue
            save_results(current_addrs, current_values, current_type, current_label)

        elif choice == '8':
            addrs, values, dtype, label = load_results()
            if addrs is not None:
                current_addrs = addrs
                current_values = values
                current_type = dtype
                current_label = label

        elif choice == '9':
            addr_str = input("  输入地址 (十六进制): ").strip()
            try:
                addr = int(addr_str, 16)
            except ValueError:
                print("  无效地址")
                continue

            v_int = read_int(handle, addr)
            v_short = read_short(handle, addr)
            v_str = read_string(handle, addr, 32)
            data = read_mem(handle, addr, 16)
            xor_val = None
            if data and len(data) >= 12:
                k1, k2 = struct.unpack('<ii', data[:8])
                if k1 != 0 and k2 != 0:
                    xor_val = k1 ^ k2

            print(f"  地址 0x{addr:X}:")
            print(f"    int:   {v_int}")
            print(f"    short: {v_short}")
            print(f"    XOR:   {xor_val} (k1=0x{data[:4].hex() if data else 0}, k2=0x{data[4:8].hex() if data and len(data)>=8 else 0})")
            print(f"    string: '{v_str}'")
            if data:
                print(f"    hex: {data.hex()}")

        elif choice == '10':
            # 确定目标地址：优先用当前搜索结果中的第一个，否则手动输入
            if current_addrs:
                print(f"  当前结果第1个地址: 0x{current_addrs[0]:08X} (标签: {current_label or '无'})")
                use_it = input("  使用该地址? (y=是 / n=手动输入): ").strip().lower()
                if use_it == 'y':
                    target = current_addrs[0]
                else:
                    target = None
            else:
                target = None

            if target is None:
                addr_str = input("  输入目标地址 (十六进制, 如 1D4CF8): ").strip()
                try:
                    target = int(addr_str, 16)
                except ValueError:
                    print("  无效地址")
                    continue

            off_str = input("  最大偏移范围 (十六进制, 默认2000): ").strip()
            try:
                max_offset = int(off_str, 16) if off_str else 0x2000
            except ValueError:
                max_offset = 0x2000

            lvl_str = input("  最大层级 (1-3, 默认2): ").strip()
            try:
                max_level = int(lvl_str) if lvl_str else 2
            except ValueError:
                max_level = 2
            max_level = max(1, min(3, max_level))

            label = input("  标签 (如HP, 回车跳过): ").strip() or current_label

            print(f"\n  正在回溯 0x{target:08X} 的指针链 (偏移范围 0x{max_offset:X}, 最多{max_level}级, 全内存扫描, 请稍候)...")
            results = pointer_scan(handle, module_regions, all_regions, target, max_offset, max_level)

            if not results:
                print("  未找到任何指针链。可能该地址不是堆对象，或偏移范围太小。")
                continue

            # 只展示解析后能读到合理值的链
            valid = []
            for b, chain in results:
                final_addr, val = read_chain(handle, b, chain)
                if final_addr is not None:
                    valid.append((b, chain, final_addr, val))

            print(f"\n  共 {len(results)} 条链，其中可解析 {len(valid)} 条:")
            show = valid[:40]
            for b, chain, final_addr, val in show:
                chain_str = ''.join(f"+0x{o:X}" for o in chain)
                print(f"    [0x{b - base_addr:08X}]{chain_str} -> 0x{final_addr:08X} = {val}")
            if len(valid) > len(show):
                print(f"    ... 其余 {len(valid)-len(show)} 条已省略 (全部会保存到文件)")

            if valid:
                save_pointer_results([(b, c) for b, c, _, _ in valid], base_addr, target, label)
                print("\n  提示: 重启游戏后使用菜单 11 验证，能读到合理值的那条即为稳定指针链。")

        elif choice == '11':
            data = load_pointer_results()
            if not data:
                continue

            chains = data.get('chains', [])
            print(f"  标签: {data.get('label','')} | 原目标: 0x{data.get('target',0):08X} | 共 {len(chains)} 条链")
            print(f"  当前模块基址: 0x{base_addr:X} (原: 0x{data.get('module_base',0):X})")

            alive = 0
            shown = 0
            for c in chains:
                base = c['base_offset'] + base_addr  # 按模块相对偏移重建，兼容ASLR
                final_addr, val = read_chain(handle, base, c['offsets'])
                if final_addr is not None:
                    alive += 1
                    if shown < 40:
                        chain_str = ''.join(f"+0x{o:X}" for o in c['offsets'])
                        print(f"    [0x{base - base_addr:08X}]{chain_str} -> 0x{final_addr:08X} = {val}")
                        shown += 1
            print(f"\n  有效链: {alive} / {len(chains)}")
            print("  若某条链读出的值等于你当前的HP/MP等数值，则它就是稳定的读取路径。")

        elif choice == '0':
            break

    CloseHandle(handle)
    print("  已退出")


if __name__ == "__main__":
    main()
