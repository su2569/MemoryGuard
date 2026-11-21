// =====================================================================
// MemoryGuardService.cpp  —  Windows 内存守护服务（Linux OOM killer 复刻版）
//
// 编译（w64devkit / GCC 15）：
//   g++ MemoryGuardService.cpp -o MemoryGuardService.exe -std=c++17 -O2 \
//       -municode -g3 -lwtsapi32 -ladvapi32 -luser32 -lpsapi
//
// 用法：
//   MemoryGuardService.exe               以服务方式运行（由 SCM 启动）
//   MemoryGuardService.exe --console     前台控制台模式（调试用）
//   MemoryGuardService.exe --score <pid> 相当于 cat /proc/<pid>/oom_score
//   MemoryGuardService.exe --adj <pid> <N>   相当于 echo N > oom_score_adj
//
// 数据目录：C:\ProgramData\MemoryGuard\  （guard.log / kills.csv）
// =====================================================================

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wtsapi32.h>

#include <string>
#include <vector>
#include <algorithm>
#include <cwctype>
#include <cstdio>
#include <climits>

// ============================ 常量与配置 ============================

static const wchar_t kDataDir[]  = L"C:\\ProgramData\\MemoryGuard";
static const wchar_t kLogFile[]  = L"C:\\ProgramData\\MemoryGuard\\guard.log";
static const wchar_t kKillCsv[]  = L"C:\\ProgramData\\MemoryGuard\\kills.csv";
static const wchar_t kIniFile[]  = L"C:\\ProgramData\\MemoryGuard\\guard.ini";   // 配置文件
static const wchar_t kAdjKey[]   = L"SOFTWARE\\MemoryGuard\\oom_score_adj";
static const wchar_t kWlKey[]    = L"SOFTWARE\\MemoryGuard\\whitelist";
static const wchar_t kSvcName[]  = L"MemoryGuard";

static double  kSoftThreshold = 85.0;            // soft：先温和回收
static double  kHardThreshold = 94.0;            // hard：直接 OOM 杀
static SIZE_T  kMinVictimWS   = 256ull << 20;    // 候选最低提交内存 256MB
static DWORD   kCheckInterval = 5000;            // 轮询间隔 ms
static DWORD   kMinProcessAge = 10000;           // 启动<10s 的进程跳过
static DWORD   kLogMaxSize    = 5ull << 20;      // 日志 5MB 轮转

// /proc/sys/vm/oom_* 风格开关
static struct {
    int dump_tasks     = 1;     // 杀前打印候选（oom_dump_tasks）
    int sigkill_only   = 1;     // 1=SIGKILL 语义（直接 Terminate）；0=先 WM_CLOSE
    int group_kill     = 1;     // oom_group_kill：杀整棵进程树
    int panic_on_oom   = 0;     // 0 关 / 1 服务退出 / 2 重启系统
    int respawn_adj    = 500;   // 复活进程附加 badness（严格复刻设为 0）
    int victim_wait_ms = 5000;  // oom_reaper 等待退出
} g_oomcfg;

static volatile LONG g_stop = 0;

// ============================ 基础工具 ============================

static std::wstring Lower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

static void ULiToMs(const FILETIME& ft, ULONGLONG* ms) {
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    *ms = u.QuadPart / 10000ULL;
}

static void CreateNestedDir(const std::wstring& dir) {
    std::wstring cur;
    for (size_t i = 0; i < dir.size(); ++i) {
        cur += dir[i];
        if (dir[i] == L'\\' && i > 3)
            CreateDirectoryW(cur.c_str(), nullptr);
    }
}

static std::wstring NowStr() {
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t buf[64];
    swprintf(buf, 64, L"%04u-%02u-%02u %02u:%02u:%02u",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// 日志（UTF-8 追加 + 轮转）
static void Log(const wchar_t* fmt, ...) {
    wchar_t buf[2048];
    va_list ap; va_start(ap, fmt);
    _vsnwprintf(buf, 2047, fmt, ap); buf[2047] = 0;
    va_end(ap);

    WIN32_FILE_ATTRIBUTE_DATA fa{};
    if (GetFileAttributesExW(kLogFile, GetFileExInfoStandard, &fa) &&
        ( (ULONGLONG)fa.nFileSizeHigh << 32 | fa.nFileSizeLow ) > kLogMaxSize) {
        std::wstring old = std::wstring(kLogFile) + L".old";
        MoveFileExW(kLogFile, old.c_str(), MOVEFILE_REPLACE_EXISTING);
    }
    HANDLE h = CreateFileW(kLogFile, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    std::wstring line = L"[" + NowStr() + L"] " + buf + L"\r\n";
    char u8[4096];
    int n = WideCharToMultiByte(CP_UTF8, 0, line.c_str(), -1, u8, sizeof(u8), nullptr, nullptr);
    if (n > 1) { DWORD w; WriteFile(h, u8, (DWORD)(n - 1), &w, nullptr); }
    CloseHandle(h);
}


// ============================ 配置文件（guard.ini） ============================
// 节名与键均为 ASCII；模板注释用英文，避免 ANSI 读取时的乱码干扰

static int IniGetInt(const wchar_t* section, const wchar_t* key, int defval) {
    return GetPrivateProfileIntW(section, key, defval, kIniFile);
}

static bool IniFileExists() {
    DWORD a = GetFileAttributesW(kIniFile);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

// 首次运行自动生成默认配置（内容取自当前内置默认值）
static void WriteDefaultIni() {
    char buf[2048];
    int n = sprintf(buf,
        "; MemoryGuard config (guard.ini)\r\n"
        "; Edit this file, then restart: sc stop MemoryGuard && sc start MemoryGuard\r\n"
        "; Every key is optional; missing keys fall back to built-in defaults.\r\n"
        "\r\n"
        "[threshold]\r\n"
        "soft = %d              ; soft threshold %% (gentle reclaim)\r\n"
        "hard = %d              ; hard threshold %% (direct OOM kill)\r\n"
        "min_victim_mb = %d     ; minimum commit for victim candidates\r\n"
        "\r\n"
        "[timing]\r\n"
        "check_interval_ms = %lu\r\n"
        "min_process_age_ms = %lu\r\n"
        "log_max_mb = %d\r\n"
        "\r\n"
        "[oom]\r\n"
        "dump_tasks = %d\r\n"
        "sigkill_only = %d\r\n"
        "group_kill = %d\r\n"
        "panic_on_oom = %d      ; 0=off 1=service exit 2=reboot\r\n"
        "respawn_adj = %d\r\n"
        "victim_wait_ms = %lu\r\n",
        (int)kSoftThreshold, (int)kHardThreshold, (int)(kMinVictimWS >> 20),
        kCheckInterval, kMinProcessAge, (int)(kLogMaxSize >> 20),
        g_oomcfg.dump_tasks, g_oomcfg.sigkill_only, g_oomcfg.group_kill,
        g_oomcfg.panic_on_oom, g_oomcfg.respawn_adj, g_oomcfg.victim_wait_ms);
    if (n <= 0) return;
    HANDLE h = CreateFileW(kIniFile, GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        Log(L"警告：guard.ini 创建失败（错误 %lu），继续使用内置默认值", GetLastError());
        return;
    }
    DWORD written = 0;
    WriteFile(h, buf, (DWORD)n, &written, nullptr);
    CloseHandle(h);
    Log(L"已自动生成默认配置 guard.ini，可编辑后重启服务生效");
}

static void LoadConfig() {
    if (!IniFileExists())
        WriteDefaultIni();   // 不存在则自动创建，然后照常读取（读回来的就是默认值）

    // ---- 阈值 ----
    kSoftThreshold = IniGetInt(L"threshold", L"soft", (int)kSoftThreshold);
    kHardThreshold = IniGetInt(L"threshold", L"hard", (int)kHardThreshold);
    int minVictimMB = IniGetInt(L"threshold", L"min_victim_mb",
                                (int)(kMinVictimWS >> 20));
    kMinVictimWS = (SIZE_T)minVictimMB << 20;

    // ---- 时机 ----
    kCheckInterval = (DWORD)IniGetInt(L"timing", L"check_interval_ms",
                                      (int)kCheckInterval);
    kMinProcessAge = (DWORD)IniGetInt(L"timing", L"min_process_age_ms",
                                      (int)kMinProcessAge);
    kLogMaxSize = (ULONGLONG)IniGetInt(L"timing", L"log_max_mb",
                                       (int)(kLogMaxSize >> 20)) << 20;

    // ---- oom 开关 ----
    g_oomcfg.dump_tasks     = IniGetInt(L"oom", L"dump_tasks",     g_oomcfg.dump_tasks);
    g_oomcfg.sigkill_only   = IniGetInt(L"oom", L"sigkill_only",   g_oomcfg.sigkill_only);
    g_oomcfg.group_kill     = IniGetInt(L"oom", L"group_kill",     g_oomcfg.group_kill);
    g_oomcfg.panic_on_oom   = IniGetInt(L"oom", L"panic_on_oom",   g_oomcfg.panic_on_oom);
    g_oomcfg.respawn_adj    = IniGetInt(L"oom", L"respawn_adj",    g_oomcfg.respawn_adj);
    g_oomcfg.victim_wait_ms = (DWORD)IniGetInt(L"oom", L"victim_wait_ms",
                                               (int)g_oomcfg.victim_wait_ms);

    // ---- 合法性钳制 ----
    if (kSoftThreshold < 50) kSoftThreshold = 50;
    if (kHardThreshold > 99) kHardThreshold = 99;
    if (kSoftThreshold >= kHardThreshold) {
        Log(L"配置警告：soft(%.0f) >= hard(%.0f)，强制 soft = hard - 3",
            kSoftThreshold, kHardThreshold);
        kSoftThreshold = kHardThreshold - 3;
    }
    if (kCheckInterval < 1000 || kCheckInterval > 600000) kCheckInterval = 5000;
    if (minVictimMB < 1) kMinVictimWS = 1 << 20;
    if (g_oomcfg.victim_wait_ms < 500) g_oomcfg.victim_wait_ms = 500;
    if (g_oomcfg.panic_on_oom < 0 || g_oomcfg.panic_on_oom > 2) g_oomcfg.panic_on_oom = 0;
    if (g_oomcfg.respawn_adj < 0 || g_oomcfg.respawn_adj > 1000) g_oomcfg.respawn_adj = 500;

    Log(L"配置已加载：soft=%.0f%% hard=%.0f%% minVictim=%IuMB interval=%lums age=%lums "
        L"dump=%d sigkill_only=%d group_kill=%d panic=%d respawn_adj=%d wait=%lums",
        kSoftThreshold, kHardThreshold, (size_t)(kMinVictimWS >> 20),
        kCheckInterval, kMinProcessAge,
        g_oomcfg.dump_tasks, g_oomcfg.sigkill_only, g_oomcfg.group_kill,
        g_oomcfg.panic_on_oom, g_oomcfg.respawn_adj, g_oomcfg.victim_wait_ms);
}

// ============================ 权限 ============================

static void EnableSeDebug() {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    AdjustTokenPrivileges(tok, FALSE, &tp, 0, nullptr, nullptr);
    CloseHandle(tok);
}

// ============================ 白名单 ============================

// HKLM\SOFTWARE\MemoryGuard\whitelist 下每个值名即白名单 exe 名；另有内置清单
static bool IsWhitelisted(const std::wstring& name, const std::wstring& path) {
    static const wchar_t* kBuiltIn[] = {
        L"winlogon.exe", L"csrss.exe", L"lsass.exe", L"services.exe",
        L"smss.exe", L"wininit.exe", L"explorer.exe", L"dwm.exe",
        L"svchost.exe", L"system", L"registry", L"idle",
        L"memoryguardservice.exe" };
    std::wstring n = Lower(name);
    for (auto k : kBuiltIn) if (n == k) return true;

    HKEY hk;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kWlKey, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return false;                       // 白名单键不存在 → 只有内置清单
    bool hit = false;
    DWORD i = 0;
    wchar_t val[256];
    for (;;) {
        DWORD sz = 256;
        LONG rc = RegEnumValueW(hk, i++, val, &sz, nullptr, nullptr, nullptr, nullptr);
        if (rc != ERROR_SUCCESS) break;
        if (Lower(val) == n) { hit = true; break; }
    }
    RegCloseKey(hk);
    (void)path;
    return hit;
}


// ============================ 击杀历史（复活检测） ============================

struct KillHistory { std::wstring name; ULONGLONG tick; };
static std::vector<KillHistory> g_killed;
static const ULONGLONG kRespawnWindow = 60000;   // 60 秒内复活视为自动重启

static bool WasRecentlyKilled(const std::wstring& name, ULONGLONG* when) {
    ULONGLONG now = GetTickCount64();
    for (auto& k : g_killed)
        if (Lower(k.name) == Lower(name) && now - k.tick < kRespawnWindow) {
            if (when) *when = k.tick;
            return true;
        }
    return false;
}
static void RecordKillHistory(const std::wstring& name) {
    g_killed.push_back({ name, GetTickCount64() });
    if (g_killed.size() > 256) g_killed.erase(g_killed.begin());
}

// ==================== oom_score_adj（注册表持久化） ====================

static bool RegGetAdj(const std::wstring& val, long* out) {
    DWORD v = 0, sz = sizeof(v);
    if (ERROR_SUCCESS == RegGetValueW(HKEY_LOCAL_MACHINE, kAdjKey, val.c_str(),
                                      RRF_RT_REG_DWORD, nullptr, &v, &sz)) {
        *out = (long)v; return true;
    }
    return false;
}
static void RegSetAdj(const std::wstring& val, long v) {
    HKEY k;
    if (ERROR_SUCCESS == RegCreateKeyW(HKEY_LOCAL_MACHINE, kAdjKey, &k)) {
        DWORD d = (DWORD)v;
        RegSetValueExW(k, val.c_str(), 0, REG_DWORD, (BYTE*)&d, sizeof(d));
        RegCloseKey(k);
    }
}

// adj 查找顺序：全路径 → name:<exe> → 白名单(-1000) → 复活进程(respawn_adj) → 0
static long OomScoreAdjOf(const std::wstring& name, const std::wstring& path) {
    long v = 0;
    if (!path.empty() && RegGetAdj(Lower(path), &v)) return v;
    if (RegGetAdj(L"name:" + Lower(name), &v)) return v;
    if (IsWhitelisted(name, path)) return -1000;
    ULONGLONG t = 0;
    if (WasRecentlyKilled(name, &t)) return g_oomcfg.respawn_adj;
    return 0;
}

// ==================== oom_badness()（仿 mm/oom_kill.c） ====================

static const unsigned OOM_PAGE_SZ = 4096;
static const long long OOM_MIN = LLONG_MIN / 2;

// points = rss + swapents + pgtables + adj * totalpages / 1000
static long long OomBadness(const PROCESS_MEMORY_COUNTERS& pmc, long adj,
                            unsigned long long totalPages) {
    if (adj <= -1000) return OOM_MIN;
    unsigned long long rss      = pmc.WorkingSetSize / OOM_PAGE_SZ;
    unsigned long long swapents = pmc.PagefileUsage / OOM_PAGE_SZ;              // 近似 swap
    unsigned long long pgtables = pmc.QuotaNonPagedPoolUsage / OOM_PAGE_SZ + 1; // 近似页表
    long long points = (long long)(rss + swapents + pgtables);
    points += (long long)adj * (long long)totalPages / 1000LL;
    return points;
}

// oom_unkillable_task()：杀了会 BSOD 的进程
static bool OomUnkillableTask(const std::wstring& name) {
    static const wchar_t* kCritical[] = {
        L"system", L"registry", L"idle", L"smss.exe", L"csrss.exe",
        L"wininit.exe", L"winlogon.exe", L"services.exe", L"lsass.exe",
        L"memoryguardservice.exe" };
    std::wstring n = Lower(name);
    for (auto c : kCritical) if (n == c) return true;
    return false;
}

// ==================== 进程信息采集 ====================

struct Victim {
    DWORD     pid = 0;
    std::wstring name, path;
    SIZE_T    ws = 0, commit = 0;
    long long oomScore = 0;
};

// 读另一个进程的命令行（ntdll 动态加载，x64 PEB 偏移）
static std::wstring ReadProcessCmdline(DWORD pid) {
    typedef LONG (NTAPI* pNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static pNtQIP NtQueryInformationProcess_ = nullptr;
    if (!NtQueryInformationProcess_) {
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        if (nt) NtQueryInformationProcess_ = (pNtQIP)GetProcAddress(nt, "NtQueryInformationProcess");
        if (!NtQueryInformationProcess_) return L"";
    }
    struct PBI { LONG exitStatus; BYTE* peb; BYTE* affinity; LONG basePri;
                 ULONG_PTR upid; ULONG_PTR parent; } pbi{};
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return L"";
    if (NtQueryInformationProcess_(h, 0, &pbi, sizeof(pbi), nullptr) != 0) { CloseHandle(h); return L""; }
    std::wstring out;
    BYTE* params = nullptr;
    if (ReadProcessMemory(h, pbi.peb + 0x20, &params, sizeof(params), nullptr) && params) {
        struct USTR { USHORT len, max; USHORT pad; wchar_t* buf; } us{};
        if (ReadProcessMemory(h, params + 0x70, &us, sizeof(us), nullptr) &&
            us.len > 0 && us.len < 32768 && us.buf) {
            std::vector<wchar_t> tmp(us.len / 2 + 1, 0);
            if (ReadProcessMemory(h, us.buf, tmp.data(), us.len, nullptr)) out.assign(tmp.data());
        }
    }
    CloseHandle(h);
    return out;
}

struct KillRecord {
    std::wstring name, path, cmdline, user;
    DWORD     pid = 0, session = 0, parentPid = 0;
    SYSTEMTIME startTime{};
    SIZE_T    ws = 0, commit = 0;
    wchar_t   killMethod[32] = L"";
    ULONGLONG freedBytes = 0;
    DWORD     elapsedMs = 0;
};

static void CollectVictimInfo(DWORD pid, KillRecord* r) {
    r->pid = pid;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (h) {
        wchar_t wpath[MAX_PATH] = L""; DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameW(h, 0, wpath, &sz)) r->path = wpath;
        FILETIME c, x, k, u; ULONGLONG startMs = 0;
        if (GetProcessTimes(h, &c, &x, &k, &u)) {
            ULiToMs(c, &startMs);
            ULARGE_INTEGER li{ c.dwLowDateTime, c.dwHighDateTime };
            FILETIME lt; FileTimeToLocalFileTime(&c, &lt);
            SYSTEMTIME st{}; FileTimeToSystemTime(&lt, &st);
            r->startTime = st;
        }
        PROCESS_MEMORY_COUNTERS pmc{};
        if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc))) {
            r->ws     = pmc.WorkingSetSize;
            r->commit = (SIZE_T)std::max<DWORD>(pmc.PagefileUsage, pmc.QuotaPeakPagedPoolUsage);
        }
        CloseHandle(h);
    }
    size_t p = r->path.find_last_of(L"\\/");
    r->name = (p == std::wstring::npos) ? r->path : r->path.substr(p + 1);

    ProcessIdToSessionId(pid, &r->session);
    LPWSTR ubuf = nullptr; DWORD ulen = 0;
    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, (DWORD)r->session,
                                    WTSUserName, &ubuf, &ulen) && ubuf) {
        r->user = ubuf;
        WTSFreeMemory(ubuf);
    }
    r->cmdline = ReadProcessCmdline(pid);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) { r->parentPid = pe.th32ParentProcessID; break; }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
}

static std::wstring CsvField(const std::wstring& s) {
    std::wstring out = s;
    bool need = out.find_first_of(L",\"\r\n") != std::wstring::npos;
    if (!need) return out;
    std::wstring q = L"\"";
    for (wchar_t c : out) { if (c == L'"') q += L"\"\""; else q += c; }
    return q + L"\"";
}

// 写 kills.csv（UTF-8，新文件写表头）
static void WriteKillRecord(const KillRecord& r) {
    bool newFile = (GetFileAttributesW(kKillCsv) == INVALID_FILE_ATTRIBUTES);
    HANDLE h = CreateFileW(kKillCsv, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    wchar_t st[32];
    swprintf(st, 32, L"%04u-%02u-%02u %02u:%02u:%02u",
             r.startTime.wYear, r.startTime.wMonth, r.startTime.wDay,
             r.startTime.wHour, r.startTime.wMinute, r.startTime.wSecond);
    std::wstring line = NowStr() + L"," + CsvField(r.name) + L"," +
        std::to_wstring(r.pid) + L"," + CsvField(r.path) + L"," +
        CsvField(r.cmdline) + L"," + std::to_wstring(r.session) + L"," +
        CsvField(r.user) + L"," + std::to_wstring(r.parentPid) + L"," +
        st + L"," + std::to_wstring(r.ws / (1024 * 1024)) + L"," +
        std::to_wstring(r.commit / (1024 * 1024)) + L"," + r.killMethod + L"," +
        std::to_wstring(r.freedBytes / (1024 * 1024)) + L"," +
        std::to_wstring(r.elapsedMs) + L"\r\n";
    if (newFile) {
        const char* hdr = "时间,进程名,PID,路径,命令行,会话ID,用户,父PID,启动时间,"
                          "工作集MB,提交MB,击杀方式,释放MB,耗时ms\r\n";
        DWORD w; WriteFile(h, hdr, (DWORD)strlen(hdr), &w, nullptr);
    }
    char u8[8192];
    int n = WideCharToMultiByte(CP_UTF8, 0, line.c_str(), -1, u8, sizeof(u8), nullptr, nullptr);
    if (n > 1) { DWORD w; WriteFile(h, u8, (DWORD)(n - 1), &w, nullptr); }
    CloseHandle(h);
}

// ==================== 第一级：温和回收（direct reclaim） ====================

static void ReclaimMemoryPass() {
    DWORD procs[4096], needed = 0;
    if (!EnumProcesses(procs, sizeof(procs), &needed)) return;
    int n = (int)(needed / sizeof(DWORD));
    for (int i = 0; i < n; ++i) {
        DWORD pid = procs[i];
        if (!pid || pid == GetCurrentProcessId()) continue;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!h) continue;
        PROCESS_MEMORY_COUNTERS pmc{};
        BOOL ok = GetProcessMemoryInfo(h, &pmc, sizeof(pmc));
        wchar_t wpath[MAX_PATH] = L""; DWORD sz = MAX_PATH;
        std::wstring name, path;
        if (QueryFullProcessImageNameW(h, 0, wpath, &sz)) {
            path = wpath;
            size_t p = path.find_last_of(L"\\/");
            name = (p == std::wstring::npos) ? path : path.substr(p + 1);
        }
        CloseHandle(h);
        if (!ok || pmc.WorkingSetSize < 128ull << 20) continue;   // 只动 128MB 以上的大户
        if (pid <= 4 || IsWhitelisted(name, path)) continue;

        HANDLE hw = OpenProcess(PROCESS_SET_QUOTA, FALSE, pid);
        if (hw) { EmptyWorkingSet(hw); CloseHandle(hw); }
    }
}

// ==================== 第二级：select_bad_process() ====================

static bool SelectBadProcess(Victim* out, unsigned long long totalPages) {
    DWORD procs[4096], needed = 0;
    if (!EnumProcesses(procs, sizeof(procs), &needed)) return false;
    int n = (int)(needed / sizeof(DWORD));
    long long best = OOM_MIN;

    for (int i = 0; i < n; ++i) {
        DWORD pid = procs[i];
        if (!pid || pid == GetCurrentProcessId()) continue;      // 不杀自身
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!h) continue;
        wchar_t wpath[MAX_PATH] = L""; DWORD sz = MAX_PATH;
        std::wstring name, path;
        if (QueryFullProcessImageNameW(h, 0, wpath, &sz)) {
            path = wpath;
            size_t p = path.find_last_of(L"\\/");
            name = (p == std::wstring::npos) ? path : path.substr(p + 1);
        }
        if (OomUnkillableTask(name)) { CloseHandle(h); continue; }
        FILETIME c, x, k, u; ULONGLONG startMs = 0;
        if (GetProcessTimes(h, &c, &x, &k, &u)) ULiToMs(c, &startMs);
        if (startMs && GetTickCount64() - startMs < kMinProcessAge) { CloseHandle(h); continue; }
        PROCESS_MEMORY_COUNTERS pmc{};
        if (!GetProcessMemoryInfo(h, &pmc, sizeof(pmc))) { CloseHandle(h); continue; }
        CloseHandle(h);
        if (pmc.PagefileUsage < kMinVictimWS) continue;

        long long points = OomBadness(pmc, OomScoreAdjOf(name, path), totalPages);
        if (points == OOM_MIN) continue;
        if (points > best) {
            best = points;
            ZeroMemory(out, sizeof(*out));
            out->pid = pid; out->name = name; out->path = path;
            out->ws = pmc.WorkingSetSize;
            out->commit = pmc.PagefileUsage;
            out->oomScore = points;
        }
    }
    return best > OOM_MIN;
}

// ==================== oom_dump_tasks() ====================

static void DumpTasks(unsigned long long totalPages) {
    struct Row { DWORD pid; std::wstring name; SIZE_T rssMB; long adj; long long pts; };
    std::vector<Row> rows;
    DWORD procs[4096], needed = 0;
    if (!EnumProcesses(procs, sizeof(procs), &needed)) return;
    int n = (int)(needed / sizeof(DWORD));
    for (int i = 0; i < n; ++i) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, procs[i]);
        if (!h) continue;
        wchar_t wpath[MAX_PATH] = L""; DWORD sz = MAX_PATH;
        std::wstring name, path;
        if (QueryFullProcessImageNameW(h, 0, wpath, &sz)) {
            path = wpath;
            size_t p = path.find_last_of(L"\\/");
            name = (p == std::wstring::npos) ? path : path.substr(p + 1);
        }
        PROCESS_MEMORY_COUNTERS pmc{};
        if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc))) {
            long adj = OomScoreAdjOf(name, path);
            long long pts = OomBadness(pmc, adj, totalPages);
            if (pts != OOM_MIN)
                rows.push_back({ procs[i], name, pmc.WorkingSetSize >> 20, adj, pts });
        }
        CloseHandle(h);
    }
    std::sort(rows.begin(), rows.end(),
              [](const Row& a, const Row& b) { return a.pts > b.pts; });
    Log(L"==== dump_tasks：击杀前候选清单 (pid / rss / adj / badness / oom_score) ====");
    int cnt = 0;
    for (auto& r : rows) {
        if (++cnt > 15) break;
        long long norm = totalPages ? r.pts * 1000LL / (long long)totalPages : 0;
        Log(L"[%5lu] %6zu MB  adj=%6ld  badness=%9lld  score=%5lld  %ls",
            r.pid, (size_t)r.rssMB, r.adj, r.pts, norm, r.name.c_str());
    }
}

// ==================== 击杀原语：SIGKILL / 组杀 / reaper / panic ====================

static void TerminatePid(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    if (h) { TerminateProcess(h, 137); CloseHandle(h); }   // 137 = 128+SIGKILL(9)
}

// oom_group_kill：先递归杀子进程，再杀自己
static void KillProcessTree(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ParentProcessID == pid && pe.th32ProcessID != pid)
                    KillProcessTree(pe.th32ProcessID);
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    TerminatePid(pid);
}

// 优雅关闭尝试（sigkill_only=0 时先走 WM_CLOSE，3 秒不退再 Terminate）
struct EnumCtx { DWORD pid; bool sent; };
static BOOL CALLBACK EnumSendClose(HWND hwnd, LPARAM lp) {
    EnumCtx* ctx = (EnumCtx*)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == ctx->pid && IsWindowVisible(hwnd)) {
        PostMessageW(hwnd, WM_CLOSE, 0, 0);
        ctx->sent = true;
    }
    return TRUE;
}
static void GracefulThenKill(DWORD pid) {
    EnumCtx ctx{ pid, false };
    EnumWindows(EnumSendClose, (LPARAM)&ctx);
    if (ctx.sent) {
        HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
        if (h) {
            if (WaitForSingleObject(h, 3000) == WAIT_OBJECT_0) { CloseHandle(h); return; }
            CloseHandle(h);
        }
    }
    TerminatePid(pid);
}

// oom_reaper：等 mm 消失，统计释放量
static ULONGLONG ReapVictim(DWORD pid, const Victim& v) {
    MEMORYSTATUSEX b{}; b.dwLength = sizeof(b); GlobalMemoryStatusEx(&b);
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (h) { WaitForSingleObject(h, (DWORD)g_oomcfg.victim_wait_ms); CloseHandle(h); }
    MEMORYSTATUSEX a{}; a.dwLength = sizeof(a); GlobalMemoryStatusEx(&a);
    return a.ullAvailPhys > b.ullAvailPhys ? a.ullAvailPhys - b.ullAvailPhys
                                           : v.ws + v.commit;
}

static void OomPanic() {
    if (g_oomcfg.panic_on_oom == 1) { Log(L"panic_on_oom=1：服务退出"); ExitProcess(2); }
    if (g_oomcfg.panic_on_oom == 2) {
        Log(L"panic_on_oom=2：10 秒后重启系统");
        HANDLE tok;
        if (OpenProcessToken(GetCurrentProcess(),
                             TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
            TOKEN_PRIVILEGES tp{};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            LookupPrivilegeValueW(nullptr, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid);
            AdjustTokenPrivileges(tok, FALSE, &tp, 0, nullptr, nullptr);
            CloseHandle(tok);
        }
        InitiateSystemShutdownW(nullptr, (LPWSTR)L"MemoryGuard panic_on_oom", 10, TRUE, TRUE);
        ExitProcess(3);
    }
}

// ==================== oom_kill_process() ====================

static void OomKillProcess(const Victim& v, unsigned long long totalPages) {
    long adj = OomScoreAdjOf(v.name, v.path);
    long long norm = totalPages ? v.oomScore * 1000LL / (long long)totalPages : 0;
    Log(L"oom-kill：击杀 pid=%lu %ls badness=%lld oom_score=%lld adj=%ld",
        v.pid, v.name.c_str(), v.oomScore, norm, adj);
    if (g_oomcfg.dump_tasks) DumpTasks(totalPages);

    KillRecord r;
    CollectVictimInfo(v.pid, &r);
    ULONGLONG t0 = GetTickCount64();

    if (g_oomcfg.sigkill_only) {
        if (g_oomcfg.group_kill) KillProcessTree(v.pid);
        else                     TerminatePid(v.pid);
        lstrcpyW(r.killMethod, L"SIGKILL");
    } else {
        if (g_oomcfg.group_kill) KillProcessTree(v.pid);
        else                     GracefulThenKill(v.pid);
        lstrcpyW(r.killMethod, L"WM_CLOSE");
    }

    r.freedBytes = ReapVictim(v.pid, v);
    r.elapsedMs  = (DWORD)(GetTickCount64() - t0);
    WriteKillRecord(r);
    RecordKillHistory(v.name);
    Log(L"oom-kill 完成：%ls 释放 %Iu MB，耗时 %lu ms",
        v.name.c_str(), (size_t)(r.freedBytes >> 20), r.elapsedMs);
}

// ==================== 监控主循环 ====================

static void MonitorLoop() {
    Log(L"监控循环启动：软阈值 %.0f%% / 硬阈值 %.0f%%，候选最低提交 %Iu MB",
        kSoftThreshold, kHardThreshold, (size_t)(kMinVictimWS >> 20));
    while (!g_stop) {
        MEMORYSTATUSEX ms{}; ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);
        unsigned load = ms.dwMemoryLoad;
        if (load < (unsigned)kSoftThreshold) { Sleep(kCheckInterval); continue; }

        bool hard = load >= (unsigned)kHardThreshold;
        if (!hard) {
            // soft：先温和回收（≈ direct reclaim），无效再升级
            Log(L"内存 %u%% ≥ 软阈值 %.0f%%，执行温和回收...", load, kSoftThreshold);
            ReclaimMemoryPass();
            Sleep(2500);
            MEMORYSTATUSEX ms2{}; ms2.dwLength = sizeof(ms2);
            GlobalMemoryStatusEx(&ms2);
            if (ms2.dwMemoryLoad < (unsigned)kSoftThreshold) {
                Log(L"回收有效，内存回落至 %u%%，无需击杀", ms2.dwMemoryLoad);
                continue;
            }
            Log(L"回收不足（%u%%），进入 out_of_memory()", ms2.dwMemoryLoad);
        } else {
            Log(L"内存 %u%% ≥ 硬阈值 %.0f%%，直接进入 out_of_memory()",
                load, kHardThreshold);
        }

        // OOM 打分选victim
        unsigned long long totalPages = ms.ullTotalPhys / OOM_PAGE_SZ;
        Victim v{};
        if (!SelectBadProcess(&v, totalPages)) {
            Log(L"oom：未找到可击杀的候选进程");
            Sleep(kCheckInterval);
            continue;
        }
        OomKillProcess(v, totalPages);
        if (g_oomcfg.panic_on_oom) { OomPanic(); continue; }

        // 内核语义：杀后如果分配仍失败会再次触发 OOM → 下一轮自动重查
        Sleep(1000);
    }
    Log(L"监控循环停止");
}

// ==================== 服务框架 ====================

static SERVICE_STATUS         g_status{};
static SERVICE_STATUS_HANDLE  g_hStatus = nullptr;

static void SetSvcStatus(DWORD state, DWORD exitCode = 0, DWORD wait = 0) {
    g_status.dwCurrentState  = state;
    g_status.dwWin32ExitCode = exitCode;
    g_status.dwWaitHint      = wait;
    if (state == SERVICE_START_PENDING)  g_status.dwControlsAccepted = 0;
    else                                 g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    if (state == SERVICE_RUNNING || state == SERVICE_STOPPED) g_status.dwCheckPoint = 0;
    else g_status.dwCheckPoint++;
    SetServiceStatus(g_hStatus, &g_status);
}

static VOID WINAPI SvcCtrlHandler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        SetSvcStatus(SERVICE_STOP_PENDING, 0, 3000);
        InterlockedExchange(&g_stop, 1);
    }
}

static VOID WINAPI SvcMain(DWORD, LPWSTR*) {
    g_hStatus = RegisterServiceCtrlHandlerW(kSvcName, SvcCtrlHandler);
    if (!g_hStatus) return;
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    SetSvcStatus(SERVICE_START_PENDING, 0, 3000);

    EnableSeDebug();
    CreateNestedDir(kDataDir);
    LoadConfig();
    SetSvcStatus(SERVICE_RUNNING);
    Log(L"服务已启动（SCM 模式）");

    MonitorLoop();

    SetSvcStatus(SERVICE_STOPPED);
}

// ==================== CLI（/proc 风格） ====================

static void FillNamePath(DWORD pid, std::wstring* name, std::wstring* path) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return;
    wchar_t wpath[MAX_PATH] = L""; DWORD sz = MAX_PATH;
    if (QueryFullProcessImageNameW(h, 0, wpath, &sz)) {
        *path = wpath;
        size_t p = path->find_last_of(L"\\/");
        *name = (p == std::wstring::npos) ? *path : path->substr(p + 1);
    }
    CloseHandle(h);
}

// 控制台输出（中文安全）：控制台用 WriteConsoleW 直写宽字符，绕开一切 locale/代码页；
// 重定向到文件/管道时写 UTF-8 字节
static void Out(const wchar_t* fmt, ...) {
    wchar_t buf[2048];
    va_list ap; va_start(ap, fmt);
    _vsnwprintf(buf, 2047, fmt, ap); buf[2047] = 0;
    va_end(ap);

    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (h && h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode)) {
        DWORD w;
        WriteConsoleW(h, buf, (DWORD)wcslen(buf), &w, nullptr);
    } else {
        char u8[4096];
        int n = WideCharToMultiByte(CP_UTF8, 0, buf, -1, u8, sizeof(u8), nullptr, nullptr);
        if (n > 0) { DWORD w; WriteFile(h, u8, (DWORD)(n - 1), &w, nullptr); }
    }
}

static int CmdScore(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { Out(L"找不到进程 %lu\n", pid); return 1; }
    wchar_t wpath[MAX_PATH] = L""; DWORD sz = MAX_PATH;
    std::wstring name, path;
    if (QueryFullProcessImageNameW(h, 0, wpath, &sz)) {
        path = wpath;
        size_t p = path.find_last_of(L"\\/");
        name = (p == std::wstring::npos) ? path : path.substr(p + 1);
    }
    PROCESS_MEMORY_COUNTERS pmc{};
    GetProcessMemoryInfo(h, &pmc, sizeof(pmc));
    CloseHandle(h);
    MEMORYSTATUSEX ms{}; ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    unsigned long long totalPages = ms.ullTotalPhys / OOM_PAGE_SZ;
    long adj = OomScoreAdjOf(name, path);
    long long pts = OomBadness(pmc, adj, totalPages);
    long long norm = pts == OOM_MIN ? -1000
                    : pts * 1000LL / (long long)totalPages;
    Out(L"PID %lu：%ls\n", pid, name.c_str());
    Out(L"路径：%ls\n", path.c_str());
    Out(L"物理内存(RSS)：%Iu MB　　提交内存：%Iu MB\n",
            (size_t)(pmc.WorkingSetSize >> 20), (size_t)(pmc.PagefileUsage >> 20));
    Out(L"oom_score_adj：%ld\n", adj);
    Out(L"oom_score：%lld（badness %lld）\n", norm, pts);
    return 0;
}

static int CmdAdj(DWORD pid, long v) {
    if (v < -1000 || v > 1000) { Out(L"adj 取值范围 -1000..1000\n"); return 1; }
    std::wstring name, path;
    FillNamePath(pid, &name, &path);
    if (path.empty()) { Out(L"找不到进程 %lu\n", pid); return 1; }
    RegSetAdj(Lower(path), v);
    Out(L"已将 %ls 的 oom_score_adj 设为 %ld\n", path.c_str(), v);
    return 0;
}

static int Usage() {
    Out(L"MemoryGuardService — Windows 内存守护服务（Linux OOM killer 复刻版）\n\n");
    Out(L"用法：\n");
    Out(L"  （无参数）                        以服务方式运行（由 SCM 启动；双击则回落控制台模式）\n");
    Out(L"  MemoryGuardService.exe --console  前台控制台模式（调试用）\n");
    Out(L"  MemoryGuardService.exe --score <pid>   查看 /proc/<pid>/oom_score 等价信息\n");
    Out(L"  MemoryGuardService.exe --adj <pid> <-1000..1000>  设置 oom_score_adj（持久化）\n");
    Out(L"  MemoryGuardService.exe --help     显示本帮助\n");
    Out(L"\n数据目录：C:\\ProgramData\\MemoryGuard\\  (guard.log / kills.csv)\n");
    return 0;
}

// ==================== 入口 ====================

static int RunConsole() {
    EnableSeDebug();
    CreateNestedDir(kDataDir);
    LoadConfig();
    Log(L"控制台模式启动");
    Out(L"MemoryGuard 控制台模式（软阈值 %.0f%% / 硬阈值 %.0f%%），Ctrl+C 退出。\n",
        kSoftThreshold, kHardThreshold);
    SetConsoleCtrlHandler([](DWORD t) -> BOOL {
        if (t == CTRL_C_EVENT || t == CTRL_CLOSE_EVENT) {
            InterlockedExchange(&g_stop, 1);
            return TRUE;
        }
        return FALSE;
    }, TRUE);
    MonitorLoop();
    Log(L"控制台模式停止");
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);

    if (argc >= 2 && (!wcscmp(argv[1], L"--help") || !wcscmp(argv[1], L"-h") ||
                      !wcscmp(argv[1], L"-help") || !wcscmp(argv[1], L"/?")))
        return Usage();

    if (argc >= 3 && !wcscmp(argv[1], L"--score")) return CmdScore((DWORD)_wtoi(argv[2]));
    if (argc >= 4 && !wcscmp(argv[1], L"--adj"))  return CmdAdj((DWORD)_wtoi(argv[2]), wcstol(argv[3], nullptr, 10));
    if (argc >= 2 && !wcscmp(argv[1], L"--console")) return RunConsole();

    // 未知参数：不猜意图，直接拒绝（防止误入监控循环）
    if (argc >= 2) {
        Out(L"未知参数：%ls\n\n", argv[1]);
        return Usage();
    }

    // 真正无参数：尝试以服务方式接入 SCM；双击则回落到 console 模式
    SERVICE_TABLE_ENTRYW tbl[] = { { (LPWSTR)kSvcName, SvcMain }, { nullptr, nullptr } };
    if (!StartServiceCtrlDispatcherW(tbl)) {
        DWORD e = GetLastError();
        if (e == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            Out(L"非 SCM 启动，回落到控制台模式。\n");
            return RunConsole();
        }
        Out(L"StartServiceCtrlDispatcher 失败，错误码 %lu\n", e);
        return 1;
    }
    return 0;
}