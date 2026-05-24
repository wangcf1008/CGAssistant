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

        elif choice == '0':
            break

    CloseHandle(handle)
    print("  已退出")


if __name__ == "__main__":
    main()
