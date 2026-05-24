// 外部进程读取示例 - 最不容易被检测的方式
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>

// 从gameservice.h复制的数据结构定义
namespace CGA {
    struct CXorValue {
        int unknown;
        int key1;
        int key2;
        unsigned char refcount;
        
        int decode() {
            return key1 ^ key2;
        }
    };

    // 简化的玩家信息结构
    struct SimplePlayerInfo {
        char name[32];
        int hp;
        int maxhp;
        int mp;
        int maxmp;
        int level;
        int gold;
        int x, y;
    };
}

// ==========================================
// 配置 - 根据你游戏的版本修改这些偏移
// ==========================================
struct GameConfig {
    const char* windowClass;     // 窗口类名
    const char* windowTitle;     // 窗口标题
    DWORD_PTR playerBaseOffset;  // 玩家数据指针偏移
    DWORD_PTR nameOffset;        // 名字偏移
    DWORD_PTR xPosOffset;        // X坐标偏移
    DWORD_PTR yPosOffset;        // Y坐标偏移
};

// 魔力宝贝示例配置（需要根据实际版本修改）
GameConfig g_config = {
    "魔力宝贝",                 // 窗口类名
    NULL,                       // 窗口标题
    0xCAEF88,                   // 玩家数据指针偏移 (cg_se_3000版本)
    0xA150B0,                   // 名字偏移
    0x8B03B4,                   // X坐标偏移
    0x8B03E4                    // Y坐标偏移
};

// ==========================================
// 工具函数
// ==========================================

// 通过窗口查找进程ID
DWORD FindProcessIdByWindow(const char* className, const char* title) {
    HWND hwnd = FindWindowA(className, title);
    if (!hwnd) return 0;
    
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    return pid;
}

// 安全读取进程内存
bool SafeReadMemory(HANDLE hProcess, DWORD_PTR address, void* buffer, SIZE_T size) {
    SIZE_T bytesRead;
    return ReadProcessMemory(hProcess, (LPCVOID)address, buffer, size, &bytesRead) && (bytesRead == size);
}

// 读取指针链
DWORD_PTR ReadPointerChain(HANDLE hProcess, DWORD_PTR base, const std::vector<DWORD>& offsets) {
    DWORD_PTR address = base;
    for (DWORD offset : offsets) {
        if (!SafeReadMemory(hProcess, address, &address, sizeof(address))) {
            return 0;
        }
        address += offset;
    }
    return address;
}

// ==========================================
// 主程序
// ==========================================
int main() {
    printf("=== 外部进程读取示例 ===\n\n");
    
    // 1. 查找游戏进程
    DWORD pid = FindProcessIdByWindow(g_config.windowClass, g_config.windowTitle);
    if (!pid) {
        printf("错误: 未找到游戏窗口\n");
        printf("请检查窗口类名是否正确\n");
        system("pause");
        return 1;
    }
    printf("找到游戏进程 ID: %d\n", pid);
    
    // 2. 打开进程
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        printf("错误: 无法打开进程 (Error: %d)\n", GetLastError());
        printf("请尝试以管理员身份运行\n");
        system("pause");
        return 1;
    }
    printf("成功打开进程\n\n");
    
    // 3. 获取游戏基址
    HMODULE hGameBase = NULL;
    HMODULE hModules[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        hGameBase = hModules[0];  // 第一个模块通常是exe本身
        printf("游戏基址: 0x%p\n", hGameBase);
    }
    
    if (!hGameBase) {
        printf("警告: 无法获取游戏基址，部分功能可能受限\n");
    }
    
    // 4. 循环读取数据
    printf("\n=== 开始读取数据 ===\n");
    while (true) {
        // 读取玩家名字
        char name[256] = {0};
        if (hGameBase && g_config.nameOffset) {
            SafeReadMemory(hProcess, (DWORD_PTR)hGameBase + g_config.nameOffset, name, sizeof(name));
        }
        
        // 读取坐标 (使用XorValue)
        int x = 0, y = 0;
        if (hGameBase) {
            CGA::CXorValue xvX, xvY;
            if (SafeReadMemory(hProcess, (DWORD_PTR)hGameBase + g_config.xPosOffset, &xvX, sizeof(xvX))) {
                x = xvX.decode();
            }
            if (SafeReadMemory(hProcess, (DWORD_PTR)hGameBase + g_config.yPosOffset, &xvY, sizeof(xvY))) {
                y = xvY.decode();
            }
        }
        
        // 输出
        printf("\r玩家: %-20s 坐标: (%5d, %5d)", 
               name[0] ? name : "(未知)", x, y);
        
        Sleep(100);
    }
    
    CloseHandle(hProcess);
    return 0;
}
