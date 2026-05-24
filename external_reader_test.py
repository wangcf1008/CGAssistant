"""
CGAssistant 外部读取测试脚本
====================================
通过 ReadProcessMemory 从外部读取游戏数据，不注入任何DLL。

使用方法：
1. 安装 Python 3.x (https://www.python.org/downloads/)
2. 以管理员身份打开命令提示符 (CMD)
3. 运行: python external_reader_test.py

如果游戏版本偏移不匹配，请修改下方 GAME_VERSION 配置。
"""

import ctypes
import ctypes.wintypes as wintypes
import struct
import sys
import time
import os

# =============================================
# Windows API 声明
# =============================================
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002

class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG),
    ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD),
    ]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
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
    hProcess = GetCurrentProcess()
    if not OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(hToken)):
        print(f"  [!] OpenProcessToken 失败: Error={ctypes.get_last_error()}")
        return False

    luid = LUID()
    if not LookupPrivilegeValueA(None, b"SeDebugPrivilege", ctypes.byref(luid)):
        print(f"  [!] LookupPrivilegeValue 失败: Error={ctypes.get_last_error()}")
        CloseHandle(hToken)
        return False

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

    if not AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), 0, None, None):
        print(f"  [!] AdjustTokenPrivileges 失败: Error={ctypes.get_last_error()}")
        CloseHandle(hToken)
        return False

    err = ctypes.get_last_error()
    CloseHandle(hToken)

    if err != 0:
        print(f"  [!] AdjustTokenPrivileges 返回错误: Error={err}")
        return False

    return True

# =============================================
# 游戏版本配置 - 根据你的游戏版本选择或修改
# =============================================
# 从 gameservice.cpp Initialize 函数中提取的偏移
# CONVERT_GAMEVAR(type, offset) 表示: 地址 = 游戏EXE基址 + offset

VERSIONS = {
    "cg_item_6000": {
        "description": "魔力宝贝 item_6000 版本 (最常见)",
        "window_class": "魔力宝贝",
        "player_base_offset": 0xE12C30,     # g_playerBase_cgitem (直接指针)
        "is_player_base_ptr_to_ptr": False,  # 直接指针，不是指针的指针
        "is_ingame_offset": 0xBDBA78,        # g_is_ingame
        "player_name_offset": 0xBDB998,      # g_player_name
    },
    "cg_se_3000": {
        "description": "魔力宝贝 se_3000 版本",
        "window_class": "魔力宝贝",
        "player_base_offset": 0xCAEF88,      # g_playerBase (指针的指针)
        "is_player_base_ptr_to_ptr": True,    # playerbase_t** 需要两次解引用
        "is_ingame_offset": 0xA15190,         # g_is_ingame
        "player_name_offset": 0xA150B0,       # g_player_name
    },
}

# 当前使用的版本 (修改这里切换版本)
GAME_VERSION = "cg_item_6000"

# =============================================
# 数据结构偏移 (从 gameservice.h playerbase_t 提取)
# =============================================
# CXorValue: int unknown(4) + int key1(4) + int key2(4) + uchar refcount(1) + padding(3) = 16 bytes
XOR_VALUE_SIZE = 16

OFFSETS = {
    "race": 0,
    "level": 4,
    "hp": 24,           # CXorValue
    "maxhp": 40,        # CXorValue
    "mp": 56,           # CXorValue
    "maxmp": 72,        # CXorValue
    "health": 236,      # int (受伤程度, 0=绿/健康, 100=红/重伤)
    "souls": 240,       # int (灵魂值)
    "gold": 244,        # int (金币)
    "name": 256,        # char[17]
    "direction": 380,   # int
    "iteminfos": 412,   # item_info_t[40] 或 [28]
}

# item_info_t 偏移 (sizeof = 0x65C = 1628)
ITEM_INFO_SIZE = 0x65C
ITEM_OFFSETS = {
    "valid": 0,             # short
    "name": 2,              # char[46]
    "image_id": 1592,       # int
    "level": 1596,          # int
    "item_id": 1600,        # int
    "count": 1604,          # int
    "type": 1608,           # int
    "assessed": 1620,       # int
}

# 装备栏8格 + 背包格数
EQUIP_SLOTS = 8
BACKPACK_SLOTS = 20  # cg_item_6000 有20格背包


# =============================================
# 读取工具函数
# =============================================
def read_memory(handle, address, size):
    buf = ctypes.create_string_buffer(size)
    bytesRead = ctypes.c_size_t()
    result = ReadProcessMemory(handle, address, buf, size, ctypes.byref(bytesRead))
    if not result or bytesRead.value != size:
        return None
    return buf.raw


def read_int(handle, address):
    data = read_memory(handle, address, 4)
    if data is None:
        return None
    return struct.unpack('<i', data)[0]


def read_short(handle, address):
    data = read_memory(handle, address, 2)
    if data is None:
        return None
    return struct.unpack('<h', data)[0]


def read_uint(handle, address):
    data = read_memory(handle, address, 4)
    if data is None:
        return None
    return struct.unpack('<I', data)[0]


def read_string(handle, address, max_len=256):
    data = read_memory(handle, address, max_len)
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
    data = read_memory(handle, address, XOR_VALUE_SIZE)
    if data is None:
        return None
    unknown, key1, key2 = struct.unpack('<iii', data[:12])
    return key1 ^ key2


# =============================================
# 查找游戏进程
# =============================================
def find_game_process(config):
    print(f"  正在启用调试权限...")
    if enable_debug_privilege():
        print(f"  调试权限已启用")
    else:
        print(f"  调试权限启用失败，继续尝试...")

    hwnd = FindWindowA(config["window_class"].encode('gbk'), None)
    if not hwnd:
        hwnd = FindWindowA(config["window_class"].encode('utf-8'), None)
    if not hwnd:
        hwnd = FindWindowA(None, None)
        print(f"  未找到类名为 '{config['window_class']}' 的窗口")
        print(f"  尝试枚举所有窗口...")
        return None, None, None

    pid = wintypes.DWORD()
    GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    pid = pid.value

    handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        err = ctypes.get_last_error()
        print(f"  OpenProcess 失败 (PID={pid}, Error={err})，尝试仅 VM_READ...")
        handle = OpenProcess(PROCESS_VM_READ, False, pid)
    if not handle:
        err = ctypes.get_last_error()
        print(f"  仍然无法打开进程 (Error={err})")
        print(f"  请确认以管理员身份运行此脚本")
        return None, None, None

    hModules = (wintypes.HMODULE * 1024)()
    cbNeeded = wintypes.DWORD()
    base_addr = None

    if EnumProcessModules(handle, hModules, ctypes.sizeof(hModules), ctypes.byref(cbNeeded)):
        base_addr = hModules[0]
        modName = ctypes.create_string_buffer(260)
        GetModuleBaseNameA(handle, base_addr, modName, 260)
        exe_name = modName.value.decode('latin-1', errors='replace')
        print(f"  游戏模块: {exe_name}, 基址: 0x{base_addr:X}")
    else:
        print(f"  EnumProcessModules 失败，使用默认基址 0x400000")
        base_addr = 0x400000

    return handle, pid, base_addr


# =============================================
# 读取玩家数据
# =============================================
def read_player_info(handle, base_addr, config):
    player_base_offset = config["player_base_offset"]
    player_addr = base_addr + player_base_offset

    if config["is_player_base_ptr_to_ptr"]:
        ptr1 = read_uint(handle, player_addr)
        if ptr1 is None or ptr1 == 0:
            return None
        ptr2 = read_uint(handle, ptr1)
        if ptr2 is None or ptr2 == 0:
            return None
        player_data_addr = ptr2
    else:
        ptr = read_uint(handle, player_addr)
        if ptr is None or ptr == 0:
            return None
        player_data_addr = ptr

    hp = read_xor_value(handle, player_data_addr + OFFSETS["hp"])
    maxhp = read_xor_value(handle, player_data_addr + OFFSETS["maxhp"])
    mp = read_xor_value(handle, player_data_addr + OFFSETS["mp"])
    maxmp = read_xor_value(handle, player_data_addr + OFFSETS["maxmp"])
    health = read_int(handle, player_data_addr + OFFSETS["health"])
    level = read_int(handle, player_data_addr + OFFSETS["level"])
    gold = read_int(handle, player_data_addr + OFFSETS["gold"])
    souls = read_int(handle, player_data_addr + OFFSETS["souls"])
    name = read_string(handle, player_data_addr + OFFSETS["name"], 17)

    return {
        "name": name,
        "level": level,
        "hp": hp,
        "maxhp": maxhp,
        "mp": mp,
        "maxmp": maxmp,
        "health": health,
        "souls": souls,
        "gold": gold,
        "player_data_addr": player_data_addr,
    }


def read_items(handle, player_data_addr, count=BACKPACK_SLOTS):
    items = []
    item_base_addr = player_data_addr + OFFSETS["iteminfos"]

    for i in range(EQUIP_SLOTS + count):
        item_addr = item_base_addr + i * ITEM_INFO_SIZE
        valid = read_short(handle, item_addr + ITEM_OFFSETS["valid"])

        if valid is None or valid == 0:
            items.append(None)
            continue

        name = read_string(handle, item_addr + ITEM_OFFSETS["name"], 46)
        item_id = read_int(handle, item_addr + ITEM_OFFSETS["item_id"])
        count_val = read_int(handle, item_addr + ITEM_OFFSETS["count"])
        item_level = read_int(handle, item_addr + ITEM_OFFSETS["level"])
        item_type = read_int(handle, item_addr + ITEM_OFFSETS["type"])
        image_id = read_int(handle, item_addr + ITEM_OFFSETS["image_id"])

        items.append({
            "slot": i,
            "name": name,
            "item_id": item_id,
            "count": count_val,
            "level": item_level,
            "type": item_type,
            "image_id": image_id,
        })

    return items


# =============================================
# 显示函数
# =============================================
def health_status(health):
    if health is None:
        return "未知"
    if health == 0:
        return "健康(绿)"
    elif health <= 20:
        return "轻伤(黄)"
    elif health <= 50:
        return "中伤(橙)"
    elif health <= 80:
        return "重伤(红)"
    else:
        return "濒死(深红)"


def hp_bar(current, maximum, width=20):
    if current is None or maximum is None or maximum == 0:
        return "?" * width
    filled = int(width * current / maximum)
    return "█" * filled + "░" * (width - filled)


EQUIP_NAMES = ["帽子", "衣服", "右手", "左手", "鞋子", "饰品1", "饰品2", "水晶"]


def print_status(player, items):
    os.system('cls' if os.name == 'nt' else 'clear')

    print("=" * 60)
    print("  CGAssistant 外部读取测试 (ReadProcessMemory)")
    print("=" * 60)

    if player is None:
        print("\n  [!] 无法读取玩家数据，可能原因：")
        print("      1. 游戏版本偏移不匹配")
        print("      2. 角色尚未进入游戏")
        print("      3. 游戏进程未找到")
        print("\n  请检查上方 GAME_VERSION 配置是否正确")
        return

    name = player.get("name", "?")
    level = player.get("level", "?")
    hp = player.get("hp", "?")
    maxhp = player.get("maxhp", "?")
    mp = player.get("mp", "?")
    maxmp = player.get("maxmp", "?")
    health = player.get("health", 0)
    souls = player.get("souls", "?")
    gold = player.get("gold", "?")

    print(f"\n  角色名称: {name}")
    print(f"  等    级: {level}")
    print()

    if isinstance(hp, int) and isinstance(maxhp, int) and maxhp > 0:
        pct = hp * 100 / maxhp
        print(f"  生命值: {hp:>6} / {maxhp:<6}  [{hp_bar(hp, maxhp)}] {pct:.1f}%")
    else:
        print(f"  生命值: {hp} / {maxhp}")

    if isinstance(mp, int) and isinstance(maxmp, int) and maxmp > 0:
        pct = mp * 100 / maxmp
        print(f"  魔法值: {mp:>6} / {maxmp:<6}  [{hp_bar(mp, maxmp)}] {pct:.1f}%")
    else:
        print(f"  魔法值: {mp} / {maxmp}")

    print()
    print(f"  受伤状态: {health_status(health)}  (数值={health}, 0=健康)")
    print(f"  灵 魂 值: {souls}")
    print(f"  金    币: {gold}")

    print()
    print("-" * 60)
    print("  装备栏:")
    print("-" * 60)

    if items:
        for i in range(EQUIP_SLOTS):
            item = items[i] if i < len(items) else None
            slot_name = EQUIP_NAMES[i] if i < len(EQUIP_NAMES) else f"装备{i}"
            if item and item.get("name"):
                print(f"  [{slot_name:>4}] {item['name']}")
            else:
                print(f"  [{slot_name:>4}] (空)")

    print()
    print("-" * 60)
    print("  背包物品 (20格):")
    print("-" * 60)

    if items:
        for i in range(EQUIP_SLOTS, EQUIP_SLOTS + BACKPACK_SLOTS):
            item = items[i] if i < len(items) else None
            slot = i - EQUIP_SLOTS
            if item and item.get("name"):
                count_str = f"x{item['count']}" if item.get('count', 0) > 1 else ""
                type_str = ""
                t = item.get('type', 0)
                if t == 10:
                    type_str = "[刀剑]"
                elif t == 11:
                    type_str = "[枪矛]"
                elif t == 12:
                    type_str = "[斧锤]"
                elif t == 13:
                    type_str = "[弓箭]"
                elif t == 14:
                    type_str = "[杖]"
                elif t == 16:
                    type_str = "[盾]"
                elif t == 17:
                    type_str = "[铠]"
                elif t == 18:
                    type_str = "[衣服]"
                elif t == 19:
                    type_str = "[袍]"
                elif t == 20:
                    type_str = "[帽子]"
                elif t == 21:
                    type_str = "[头盔]"
                elif t == 22:
                    type_str = "[鞋]"
                elif t == 23:
                    type_str = "[靴]"
                elif t == 24:
                    type_str = "[戒指]"
                elif t == 25:
                    type_str = "[项链]"
                elif t == 26:
                    type_str = "[饰品]"
                elif t == 28:
                    type_str = "[水晶]"
                elif t == 30:
                    type_str = "[药]"
                elif t == 31:
                    type_str = "[料理]"
                elif t == 32:
                    type_str = "[材料]"
                elif t == 33:
                    type_str = "[卡片]"
                elif t == 34:
                    type_str = "[封印卡]"
                elif t == 40:
                    type_str = "[矿石]"
                elif t == 41:
                    type_str = "[木材]"
                print(f"  [{slot:>2}] {type_str}{item['name']} {count_str}")
            else:
                print(f"  [{slot:>2}] (空)")

    print()
    print("-" * 60)
    print(f"  数据地址: 0x{player.get('player_data_addr', 0):X}")
    print(f"  按 Ctrl+C 退出")
    print("-" * 60)


# =============================================
# 主程序
# =============================================
def main():
    print("=" * 60)
    print("  CGAssistant 外部读取测试")
    print("=" * 60)

    config = VERSIONS[GAME_VERSION]
    print(f"\n  当前版本: {GAME_VERSION} - {config['description']}")
    print(f"  窗口类名: {config['window_class']}")
    print(f"  玩家基址偏移: 0x{config['player_base_offset']:X}")
    print(f"  指针类型: {'指针的指针(**)' if config['is_player_base_ptr_to_ptr'] else '直接指针(*)'}")

    print(f"\n  正在查找游戏进程...")
    handle, pid, base_addr = find_game_process(config)

    if handle is None:
        print("\n  [!] 未找到游戏进程！")
        print("\n  可能的原因：")
        print("    1. 游戏未启动")
        print("    2. 窗口类名不匹配 (当前: '{}')".format(config['window_class']))
        print("    3. 没有管理员权限")
        print("\n  解决方法：")
        print("    1. 先启动游戏并进入角色")
        print("    2. 以管理员身份运行此脚本")
        print("    3. 如果窗口类名不对，修改脚本中的 window_class")
        print("\n  提示：可以用 Visual Studio 的 Spy++ 工具查看游戏窗口类名")
        input("\n  按回车键退出...")
        return

    print(f"  找到进程 PID={pid}, 基址=0x{base_addr:X}")

    is_ingame_addr = base_addr + config["is_ingame_offset"]
    ingame = read_int(handle, is_ingame_addr)
    print(f"  在线状态: {'已进入游戏' if ingame else '未进入游戏'}")

    if not ingame:
        print("\n  [!] 角色尚未进入游戏，请先登录并选择角色")
        print("  脚本将每5秒检测一次，等待进入游戏...")

    try:
        while True:
            ingame = read_int(handle, is_ingame_addr)
            if not ingame:
                time.sleep(5)
                continue

            player = read_player_info(handle, base_addr, config)
            items = None
            if player and player.get("player_data_addr"):
                items = read_items(handle, player["player_data_addr"], BACKPACK_SLOTS)

            print_status(player, items)
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n\n  已退出")
    finally:
        if handle:
            CloseHandle(handle)


if __name__ == "__main__":
    main()
