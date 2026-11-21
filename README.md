# MemoryGuard
> **修复了 Windows 没有 OOM Killer 的 BUG。**
> 把 Linux 的 OOM（Out-Of-Memory）机制——badness 打分、oom_score_adj、温和回收、临终击杀——完整复刻到 Windows 上，作为一个轻量后台服务运行。
---
## 这是什么
Linux 内核在物理内存耗尽时，会按 `badness` 分数挑出“最该死”的进程击杀，保住系统。Windows 没有这套机制——内存耗尽时只有全局性的卡死、换页风暴，或者干脆蓝屏。
MemoryGuard 补上了这块拼图：
| Linux 概念 | MemoryGuard 对应实现 |
|---|---|
| `badness` 打分 | RSS + swapents + 页表 ≈ 提交内存，除以全机总页数 × 1000 |
| `/proc/<pid>/oom_score` | `--score <pid>`，输出与 Linux 语义一致的 0~1000 分值 |
| `oom_score_adj`（-1000 ~ +1000） | `--adj <pid> <值>`，按**进程路径持久化**，重启进程后依然生效 |
| `dump_tasks` | 击杀前列出全部候选：PID / RSS / 提交 / adj / 分数 |
| `panic_on_oom` | 可选：服务退出 / 重启系统 |
| 内核线程周期回收 | 85% 软阈值先 `EmptyWorkingSet` 温和回收，94% 硬阈值才动手 |
核心原则：**能不杀就不杀，要杀就杀对**。95% 的内存紧张由软阈值阶段化解，击杀是最后一道防线；系统关键进程（lsass、csrss、svchost 等）内置不可击杀保护。
## 特性
- **双阈值防线**：软阈值（默认 85%）温和回收，硬阈值（默认 94%）OOM 击杀
- **与 Linux 一致的打分**：`badness → oom_score`，CLI 可随时查询任意进程
- **持久化豁免**：`oom_score_adj` 绑定进程路径，重启不丢
- **配置文件**：`guard.ini` 首次运行自动生成，改阈值/间隔无需重编译
- **完整审计**：`guard.log` 全程记录，`kills.csv` 击杀档案（Excel 可开）
- **日志轮转**：5MB 自动切 `.old`，不会撑爆磁盘
- **防误杀**：启动不足 10s 的进程跳过、提交内存 <256MB 不作为候选、关键进程白名单
- **服务化**：SCM 标准服务，开机自启，`sc` 全套管理
## 构建
需 MinGW-w64（g++）：
```bash
g++ MemoryGuardService.cpp -o MemoryGuardService.exe \
    -std=c++17 -O2 -municode -g3 \
    -lwtsapi32 -ladvapi32 -luser32 -lpsapi
```
## 部署（管理员 CMD）
```cmd
sc create MemoryGuard binPath= "C:\ProgramData\MemoryGuard\MemoryGuardService.exe" start= auto DisplayName= "MemoryGuard 内存守护"
sc description MemoryGuard "Windows 内存守护服务：温和回收 + OOM killer（Linux 复刻版）"
sc start MemoryGuard
sc query MemoryGuard
```
> 注意 `binPath=`、`start=` 的**等号后必须紧跟空格**，这是 `sc` 的语法。
启动后数据目录自动就位：
```
C:\ProgramData\MemoryGuard\
├── guard.ini    配置（首次运行自动生成）
├── guard.log    运行日志（5MB 轮转）
└── kills.csv    击杀档案
```
## 使用
### CLI 查询（服务运行时也可独立使用）
```cmd
MemoryGuardService.exe --score 157200
```
```
PID 157200：QQ.exe
路径：E:\Program Files\Tencent\QQNT\QQ.exe
物理内存(RSS)：937 MB　　提交内存：1440 MB
oom_score_adj：0
oom_score：195（badness 608764）
```
```cmd
MemoryGuardService.exe --adj 157200 -1000   :: 豁免：永不被击杀
MemoryGuardService.exe --adj 157200 500     :: 打压：优先候选
MemoryGuardService.exe --console            :: 前台运行，观察实时行为
```
### 配置（`guard.ini`，改完 `sc stop` + `sc start` 生效）
```ini
[threshold]
soft = 85              ; 软阈值%（温和回收）
hard = 94              ; 硬阈值%（OOM 击杀）
min_victim_mb = 256    ; 候选最低提交内存
[timing]
check_interval_ms = 5000
min_process_age_ms = 10000
log_max_mb = 5
[oom]
dump_tasks = 1         ; 击杀前打印候选清单
sigkill_only = 1       ; 只用 TerminateProcess，不先发关闭消息
group_kill = 1         ; 连带击杀同映像的子进程
panic_on_oom = 0       ; 0=关 1=服务退出 2=重启系统
respawn_adj = 500
victim_wait_ms = 5000
```
所有键可省略，缺失回退内置默认；非法值（如 soft ≥ hard）自动纠正并记日志。
### 日常运维
```cmd
sc query MemoryGuard      :: 状态
sc stop MemoryGuard       :: 停止（秒停）
sc start MemoryGuard      :: 启动
sc delete MemoryGuard     :: 卸载（先 stop）
```
更新版本三连：
```cmd
sc stop MemoryGuard
copy /y <新exe> C:\ProgramData\MemoryGuard\
sc start MemoryGuard
```
## 运行时行为
每 5 秒轮询一次全机内存占用率：
```
占用 < 85%          → 安静睡觉
占用 ≥ 85%（软）    → 对大户 EmptyWorkingSet 温和回收，观察 2.5s
  回收有效          → 回归安静
  回收不足，≥ 94%（硬）→ out_of_memory
                       → dump_tasks 列出全部候选
                       → 选 oom_score 最高者（跳过豁免/白名单/新进程）
                       → TerminateProcess 击杀 → 记入 kills.csv
```
日志示例：
```
[2026-11-21 19:xx:xx] 服务已启动（SCM 模式）
[2026-11-21 19:xx:xx] 配置已加载：soft=85% hard=94% minVictim=256MB ...
[2026-11-21 19:xx:xx] 监控循环启动：软阈值 85% / 硬阈值 94%，候选最低提交 256 MB
[2026-11-21 19:xx:xx] 软阈值触发（88.2%），执行温和回收
[2026-11-21 19:xx:xx] 温和回收有效，释放约 612 MB
```
## 已知限制
- 单实例设计，打分基于提交内存而非 Linux 内核的精确页表统计（量级一致）
- `oom_score_adj` 按路径持久化在注册表中，卸载服务不会清理这些键
- `panic_on_oom = 2`（重启系统）需要 `SeShutdownPrivilege`，LocalSystem 默认持有
## License
MIT
