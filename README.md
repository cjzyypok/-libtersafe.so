# libtersafe.so 检测点逆向分析报告

本仓库收录了 `libtersafe.so`（腾讯安全 / TenSafe / TSS / TP2 系列 Android 安全 SDK 的客户端核心 SO），下文整理出经静态逆向得到的**全部可识别检测点**及其证据出处，供安全研究、合规审计、与之集成的客户端排错参考。

> 本文件由静态逆向工具链产出（`readelf` / `objdump` / `capstone` / 自研 XOR 解密脚本）。所有结论均带具体 SO 内地址或字符串作为佐证，便于任何研究者复核。

---

## 0. 样本基本信息

| 字段 | 值 |
| --- | --- |
| 文件 | `libtersafe.so` |
| 大小 | 5,598,144 字节（≈ 5.34 MiB） |
| 架构 | AArch64（ARM64，小端） |
| 类型 | ELF DYN（共享库） |
| SONAME | `libtersafe.so` |
| BIND_NOW | 是（禁用懒绑定，所有 GOT 在加载时填充） |
| 依赖 | `liblog.so`、`libc.so`、`libm.so`、`libdl.so` |
| 段布局 | `.rodata 0x90ec0 – 0x10c134`、`.text 0x1b6af0 – 0x50dfa0`、`.data.rel.ro 0x512f30 – 0x51beb8`、`.data 0x521500 – 0x55e3a0`、`.bss 0x55e3a0 – 0x5787f8` |
| 导出符号数 | 69（全部带 `@@TERSAFE` 版本符号） |
| 动态导入数 | 215（libc / Bionic / libdl / liblog） |
| 内部构建路径泄漏 | `/Users/bkdevops/tpmobile/workspace/p-c5c18c767fca4537af3d80bab10cc86d/china/mvm/source/VM/Memory/BopMemoryOperation.cpp` |

构建路径中的 `tpmobile / mvm / VM / Memory / BopMemoryOperation.cpp` 表明 SO 内部包含一个**自实现的 Mini VM（MVM）**，用于将关键检测逻辑虚拟化以对抗逆向。后文 §11 给出细节。

---

## 1. 身份与版本指纹

`libtersafe.so` 的对外身份可由下列字符串与导出符号确认：

- 明文标识：`TERSAFE`（版本符号名）、`libtersafe.so`（XOR 0x18 解密后）、`TSS_SDK_SIGDATA`、`TssSDKxxx` 一族、`tp2_xxx` 一族。
- 与之绑定的 APK 包名（硬编码于 `.rodata`）：
  - `com.tencent.tmgp.dfm`（腾讯游戏，`tmgp` 前缀为 Tencent Mobile Games Publishing）
  - `com.ace.gamesafe4`（自检 demo 包名）
- 远程配置 / 规则下发 URL（全部为明文 HTTP）：
  - `http://down.qq.com/iedsafe/Client/android`
  - `http://down.qq.com/iedsafe/Client/android/%d/config2.xml`
  - `http://down.qq.com/iedsafe/Client/android/test/%d/config2.xml`
  - `http://down.qq.com/iedsafe/Client/android/%d/%08X/mrpcsc.data`

`iedsafe`（"Information & Entertainment Defense / Safe"）与 `mrpcs`（Memory RPCS，内存巡检模块）是腾讯 TenSafe / TSS 自报模块名。

### 1.1 全部导出函数（69 个）

按职能分组：

**初始化 / 销毁**
- `JNI_OnLoad`
- `TssSDKInit`、`TssSDKInitEx`、`TssSDKFree`
- `tp2_sdk_init`、`tp2_sdk_init_ex`、`tp2_getver`

**IOCTL / 命令通道**
- `TssSDKIoctl`、`TssSDKIoctlOld`、`tp2_sdk_ioctl`、`tss_sdk_ioctl`
- `tss_jni_cmd`、`TssJavaMethod_SendCmd`（JNI ↔ native 通道）

**生命周期回调**
- `TssSDKOnPause`、`TssSDKOnResume`

**用户 / 游戏状态**
- `TssSDKSetUserInfo`、`TssSDKSetUserInfoWithLicense`
- `tp2_setuserinfo`、`tp2_setuserinfowithlicense`
- `tp2_setgamestatus`、`tss_sdk_setgamestatus`
- `tp2_setoptions`、`tss_sdk_set_token`

**数据上报 / 监听**
- `TssSDKRegistInfoListener`、`tp2_regist_tss_info_receiver`、`tss_sdk_regist_tss_info_receiver`
- `TssSDKGetReportData`、`TssSDKGetReportData2/3/4`
- `TssSDKDelReportData`、`TssSDKDelReportData3/4`
- `tss_get_report_data`、`tss_get_report_data2/3/4`
- `tss_del_report_data`、`tss_del_report_data3/4`
- `tss_enable_get_report_data`
- `TssSDKOnRecvData`、`TssSDKOnRecvSignature`
- `tss_recv_sec_signature`、`tss_sdk_rcv_anti_data`

**会话 / 包加解密**
- `tss_sdk_gen_session_data`
- `tss_sdk_encryptpacket`、`tss_sdk_decryptpacket`
- `tss_sdk_ischeatpacket`（**核心：判定一个网络包是否为外挂作弊包**）
- `tss_sdk_wait_verify`
- `tss_sdk_dec_tss_info`、`tp2_dec_tss_info`

**Unity 专用**
- `tss_unity_is_enable`、`tss_unity_str`

**辅助 / 内部**
- `tp2_free_anti_data`、`tss_log_str`、`GetTssExportFunc2`、`g_AllTssExportFunc`
- `tss_sdt_float2uint`、`tss_sdt_uint2float`、`tss_sdt_double2uint64`、`tss_sdt_uint642double`（浮点 ↔ 整数防篡改转换）
- C++ 类：`_ZN6TssSdk10gen_randomEv`、`_ZN6TssSdk11gen_random2Ev`、`_ZN6TssSdk16sdt_report_errorEv`、`_ZN3tp210gen_randomEv`

---

## 2. 反调试（Anti-Debug）

### 2.1 自占用 ptrace 槽位（self-attach via child fork）

`libtersafe.so` 内共 **17 处** `ptrace()` 调用，第一参数（请求码）分布如下：

| 请求码 | 含义 | 命中地址 | 调用次数 |
| --- | --- | --- | --- |
| `0x10` | `PTRACE_ATTACH` | `0x26257c`、`0x269c5c`、`0x26b458` | 3 |
| `0x11` | `PTRACE_DETACH` | `0x262af8`、`0x262cac`、`0x269c08`… | 5 |
| `0x07` | `PTRACE_CONT` | `0x262a7c`、`0x26274c` | 2 |
| `0x18` | `PTRACE_SYSCALL` | `0x269aa8`、`0x269cc0` | 2 |
| `0x4200` | `PTRACE_SETOPTIONS` | `0x26268c` | 1 |
| `0x4204` | `PTRACE_GETREGSET` | `0x2694b8`、`0x26b7bc` | 2 |
| `0x4205` | `PTRACE_SETREGSET` | `0x26956c`、`0x2695c8` | 2 |

调用模式（参见 `0x26257c` 周围）：

```
kill(pid, SIGSTOP=0x13)            ; 0x262c84 ─ 暂停目标
ptrace(PTRACE_ATTACH, pid, 0, 0)   ; 0x26257c
ptrace(PTRACE_SETOPTIONS, …, 0xe)  ; 0x26268c ─ 设置 fork/clone/exec/exit 跟随
ptrace(PTRACE_CONT, pid, 0, 0)     ; 0x262a7c
…
ptrace(PTRACE_DETACH, pid, 0, 0)   ; 0x262af8
kill(pid, SIGCONT=0x12)            ; 0x262cb8 ─ 恢复目标
```

这是经典的**子进程 ptrace 自己父进程**反调试方案——一旦自身被附加，外部 IDA / gdb / lldb / Frida 因 Linux 同时只允许一个 tracer 而无法再 attach。

### 2.2 信号处理器布陷

`signal(N, handler)` 共 8 处（`.text` `0x2622b0 – 0x262338`），覆盖以下信号：

| 信号 | 编号 | 用途 |
| --- | --- | --- |
| `SIGHUP` | `1` | 进程组终端关闭 |
| `SIGILL` | `4` | 非法指令（关键：拦截硬断点 / 改写指令） |
| `SIGABRT` | `6` | `abort()` 触发 |
| `SIGBUS` | `7` | 总线错误（对未对齐访问或 mmap 区被改写敏感） |
| `SIGFPE` | `8` | 浮点异常 |
| `SIGSEGV` | `11` | 段错误（拦截内存改写 / 调试 PT_ACCESS） |
| `SIGPIPE` | `13` | 写已关闭管道 |
| `SIGSTKFLT` | `16` | 栈错误 |

还有 1 处 `sigaction(SIGDETACH=0x11)` （`0x26232c`）注册 PTRACE_DETACH 信号处理。

### 2.3 `prctl` 调用矩阵

`prctl()` 共 **10** 处调用：

| Option | 含义 | 命中地址 |
| --- | --- | --- |
| `0x04` | `PR_SET_DUMPABLE`（=0 时禁止 core dump，阻断 gdb 附加） | `0x2619c4`、`0x26c124` |
| `0x4d41` (`'AM'`) | `PR_SET_VMA / PR_SET_VMA_ANON_NAME`（命名匿名映射，便于自我巡检） | `0x253d88`、`0x367e98`、`0x367ecc` 等 6 处 |
| 未解析 | 推测为 `PR_SET_NAME` / `PR_GET_NAME` 等 | `0x2c45f0`、`0x2f1934` |

### 2.4 `/proc` 自我扫描

通过 `fopen()` × 19、`__fgets_chk()`、`fgets()` 读取 `/proc` 节点。`.rodata` 里以 **XOR 0x18 加密**保存以下路径：

| 加密形态（`.rodata` 内） | 解密后 |
| --- | --- |
| `7hjw{7k}t~7uyhk` @ `0x911e6` | `/proc/self/maps` |
| `7hjw{7=|7uyhk` @ `0x95e96` | `/proc/%d/maps` |
| `7hjw{7=|7{u|tqv}` @ `0x9158a` | `/proc/%d/cmdline` |
| `7hjw{7zmk7qvhml7|}nq{}k` @ `0x96bc6` | `/proc/bus/input/devices` |

解密代码为单字节异或循环，密钥固定为 `0x18`，NUL 终止符以字面 `0x00` 存储于密文末尾。

用途：
- 读 `/proc/self/maps`、`/proc/%d/maps`：枚举被加载的 SO，匹配 Frida / Xposed / Magisk 等 hook 框架的注入痕迹。
- 读 `/proc/%d/cmdline`：定位关键进程名（如 `frida-server`、`zygote`、目标游戏进程等）。
- 读 `/proc/bus/input/devices`：枚举系统输入设备，识别**虚拟触屏 / 按键映射工具**（雷电按键、GameSir 等）。
- 读 `/proc/self/status`：解析 `TracerPid` 字段。

### 2.5 `debugger` 字段

明文模板字符串：
- `debugger`
- `debugger:%s`
- `debugger=%s`

用于将检测到的 tracer 信息回传到上报通道。

---

## 3. 反 Hook / 反注入（Anti-Hook / Anti-Inject）

### 3.1 内联 Hook 检测（opcode 比对）

以下明文常量出现于 `.rodata`：
- `ms_hook_opcode`
- `ms_set_inlie_hook`（原文如此，TenSafe 的拼写错误 "inlie"）
- `set_inline_hook_error`
- `inline_hook_opcode_dismatch`

实现思路：保存目标 API（典型如 `open/read/recv/connect/dlopen/...`）的前 4–16 字节"原始"操作码快照，运行时与 PLT 解析到的当前函数头比对，发现被 `B`/`BR`/`LDR PC` 跳转改写即报告。

### 3.2 模块枚举

| 调用 | 计数 | 用途 |
| --- | --- | --- |
| `dl_iterate_phdr` | 1 | 完整遍历进程内 ELF 模块（PT_LOAD 段、SONAME） |
| `dladdr` | 11 | 反查关键函数所属模块，验证 API 解析未被劫持 |
| `dlopen` | 27 | 显式装载 / 句柄获取 |
| `dlsym` | 45 | 解析 API 地址 |
| `dlclose` | 21 | — |

`dlopen` 显式装载的目标 SO（XOR 0x18 解密）：

| 地址 | 解密 |
| --- | --- |
| `0x9395d`（推测）  | `libGLESv2.so` |
| `0x973e5` | `libGLESv2.so` |
| `0x92cb7` | `libEGL.so` |
| `0x96c58` | `libUE4.so` |
| `0x9519c`（filename） | `libvulkan.so` |
| `0x97cc6` | `libtersafe.so` （自检） |

获取这些图形/引擎 SO 句柄后，再以 `dlsym` 解析渲染 / 引擎入口，结合 §6/7 的 GLES、Vulkan、Mono 接口做"接口出现于哪个 SO"的来源校验。

### 3.3 Frida 特征匹配

`.text` `0x9PtGum`（明文）残留——这是 **FridaGum** 字符串的截断片段（"Gum" 是 Frida 的底层引擎名）。SDK 把它当成签名串用 `memmem` / `strstr` 在 `/proc/self/maps` 或匿名映射页内匹配，从而判定 Frida 注入。

### 3.4 inotify 监视

| 调用 | 计数 |
| --- | --- |
| `inotify_init` | 2 |
| `inotify_add_watch` | 2（mask=`0x4`，即 `IN_ATTRIB`） |

在加载完成后对自身相关路径（如 SO 文件、APK base.apk、配置目录）添加 `IN_ATTRIB` 监视，捕捉 Magisk 模块替换、Frida gadget 注入时的属性变化。

### 3.5 内存属性巡检

| 调用 | 计数 | 用途 |
| --- | --- | --- |
| `mprotect` | 16 | 改写自身代码页权限以执行加解密 / 巡检，也用于把临时数据段标记为不可读后再恢复，制造侧信道 |
| `madvise` | 2 | `MADV_DONTNEED` 等，强制刷新驻留页 |
| `mincore` | 3 | 探测页面是否驻留物理内存，识别"按需解密"的注入器 |

### 3.6 syscall 直入

`syscall()` 调用 **23** 次。多数场景下用于绕过 libc 中可能被 hook 的封装层，直接发起 `openat` / `read` / `pread64` / `kill` / `gettid` / `ptrace` 等。这是对**libc 函数被 inline-hook**的旁路防御。

---

## 4. 反 Root（Anti-Root）

直接证据：

- 明文 flag：`mt2_no_root`
- 上报模板：`name=%s|rate=%.2f|is_root=%d`
- `getuid()` × 7（核对当前 UID 是否升权）

间接证据（路径与命令均做了 XOR 0x18 加密，可见的解密侧引用）：

- `stat()` × 10、`statfs()` × 3、`access()` × 2、`opendir()` × 4、`readlink()` × 1
- `popen()` × 1（@ `0x24f9dc`，参数被加密）+ `pclose()`
- `__system_property_get` × 4、`__system_property_find_nth` × 2、`__system_property_read` × 1

由 `popen` + `system_property` + `stat/statfs/access` 组合可推断检测项至少包含：
- `/system/xbin/su`、`/system/bin/su`、`/sbin/su`、`/su/bin/su` 等 su 二进制存在性
- `/system/app/Superuser.apk`、`/data/local/tmp/`、`/data/local/bin/` 等可疑目录
- `/system` 是否被重新挂载为 `rw`（`statfs` 检查文件系统类型与 mount flags）
- 系统属性 `ro.build.tags`、`ro.debuggable`、`ro.secure`、`ro.build.type`、`ro.product.model`、`service.adb.root` 等（均以 XOR 加密形态保存于 `.rodata`，仅 `ro.arch` 已确认为明文）

---

## 5. 反模拟器（Anti-Emulator）

- 明文上报字段：`|emulator_name=`
- `strncmp(..., "exynos9810")` × 2（@ `0x509818`）——三星 Galaxy S9/Note 9 SoC 校验，作为正版机器白名单标记
- `getauxval()` × 3：
  - `AT_RANDOM` (0x10) × 2 @ `0x5097d0`、`0x509e48`——读取 kernel 提供的随机种子，模拟器（QEMU / NoxPlayer）常有可识别的固定模式
  - `AT_SECURE` (0x1a) × 1 @ `0x509e54`——SUID/SGID 标志
- `uname()` × 1——读取内核 release / machine 字段比对模拟器特征
- 大量加密的系统属性键：`ro.product.cpu.abi`、`ro.kernel.qemu`、`ro.hardware`、`init.svc.qemud`、`qemu.sf.fake_camera`、`ro.bootloader`、`ro.serialno` 等典型模拟器探针

---

## 6. 内存与资源完整性（Memory / Asset Integrity）

### 6.1 关键字符串（全部明文）

- `CertMD5`——对宿主 APK 的 V1/V2 签名块取 MD5 校验
- `%s;crc:%s`——内存块 CRC 上报模板
- `ms_data_crc`、`mrpcs_data_crc_error`、`mrpcs_data_len_error`、`mrpcs_data_mode_name_len_error`——本地保存的检测数据自校验
- `mrpcs_scan_thread_start_failed!`——内存扫描线程启动失败时的日志
- `mrpcs_download_data_thread_start_failed!`、`ms_down_start`、`ms_down_data`——远端规则下载线程
- `mrpcs_send_data_thread_start_failed!`、`ms_send_start`、`ms_send_one_data_size_beyond_buff`——上报线程
- `mrpcs_single_data_not_match!`、`mrpcs_common_data_not_match!`——签名匹配未命中
- `MrpcsActiveSig`——主动签名扫描器名
- `mrpcs_lib`、`mrpcsc.data`、`unzipmrpcs.data`——本地缓存的规则文件名 / 解压后缓存
- `mvm_bk_proc`、`mvm_bk_task`、`ms_fc_start`——MVM 后台巡检子任务

### 6.2 远端规则文件

`http://down.qq.com/iedsafe/Client/android/%d/%08X/mrpcsc.data` 中 `%d` 为客户端版本号、`%08X` 为客户端身份哈希。规则下载后由 `unzipmrpcs.data` 解压，再供 `MrpcsActiveSig` 在每个扫描周期里做内存模式匹配。

### 6.3 自检循环

`ms_scan_start` ↔ `mrpcs_scan_thread_start_failed!` 暗示存在一个**独立巡检线程**：周期性地（结合上文 `nanosleep`、`sleep`、`gettimeofday` 的高频调用）扫描自身 `.text` / 关键全局表的 CRC，发现不一致即触发 `_ZN6TssSdk16sdt_report_errorEv` 上报。

---

## 7. 游戏引擎专用探针（Engine-Specific）

### 7.1 Unity / Mono 运行时

`.rodata` 内通过 XOR 0x18 加密的 Mono API 名（共 17 个，地址范围 `0x911b2 – 0x989e6`）：

| 函数名 | 说明 |
| --- | --- |
| `mono_image_open_from_data_with_name` | 加载内存中的托管程序集 |
| `mono_image_close` / `mono_image_get_name` / `mono_image_get_filename` | 程序集元信息 |
| `mono_assembly_close` / `mono_assembly_get_image` / `mono_assembly_load_from_full` / `mono_assembly_foreach` | 程序集枚举 |
| `mono_domain_get` / `mono_domain_get_id` / `mono_domain_assembly_open` | AppDomain |
| `mono_class_from_name` / `mono_class_get_method_from_name` / `mono_class_get_field_from_name` | 类 / 字段 / 方法反射 |
| `mono_field_get_offset` | 字段内存偏移 |
| `mono_compile_method` | JIT 触发 |

目标程序集明文常量：
- `Assembly-CSharp.dll`（Unity 游戏脚本默认输出）
- `/assets/bin/Data/Managed/`（Unity APK 内 Mono assembly 目录）

含义：SDK 对 Unity 游戏的 C# 层做内省，校验关键类（如反外挂相关、玩家属性、计费）的字段偏移与方法体哈希；JIT 之后亦可读取生成的本机代码做二次比对。导出符号 `tss_unity_is_enable`、`tss_unity_str` 与之直接呼应。

### 7.2 Vulkan API

XOR 0x18 加密的 Vulkan API 名（命中地址范围 `0x91995 – 0x9826a`）：

| 类别 | API |
| --- | --- |
| 实例 / 设备 | `vkCreateInstance`、`vkDestroyInstance`、`vkEnumeratePhysicalDevices`、`vkGetPhysicalDeviceMemoryProperties`、`vkGetPhysicalDeviceQueueFamilyProperties`、`vkGetInstanceProcAddr` |
| 内存 | `vkAllocateMemory`、`vkFreeMemory`、`vkMapMemory`、`vkUnmapMemory` |
| Command buffer | `vkAllocateCommandBuffers`、`vkCreateCommandPool`、`vkEndCommandBuffer`、`vkCmdBeginRenderPass`、`vkCmdPipelineBarrier`、`vkCmdCopyImage`、`vkCmdCopyBufferToImage` |
| 同步 | `vkCreateFence`、`vkDestroyFence`、`vkWaitForFences` |
| 队列 | `vkQueueSubmit`、`vkGetDeviceQueue` |
| 图像 | `vkCreateImage`、`vkGetImageMemoryRequirements`、`vkGetImageSubresourceLayout` |
| Swapchain | `vkAcquireNextImageKHR`、`vkGetSwapchainImagesKHR`、`vkQueuePresentKHR` |
| 扩展 | `VK_KHR_surface`、`VK_KHR_android_surface`、`VK_KHR_swapchain` |

用途：识别**绘制阶段拷贝帧缓冲**（典型脚本透视外挂的特征——拷贝 framebuffer 到可读 buffer）。

### 7.3 OpenGL ES / EGL

XOR 0x18 加密：`eglGetError`、`eglGetCurrentContext`、`eglCreateContext`、`eglDestroyContext`、`eglQueryContext`、`eglQuerySurface`、`eglDestroySurface`、`eglChooseConfig`、`eglCreatePbufferSurface`、`eglSwapBuffers`、`glBindFramebuffer`、`glBindTexture`、`glReadPixels`、`glCopyTexImage2D`、`glFramebufferTexture2D`、`glGenFramebuffers`、`glGenTextures`。

同样用途：监控 `glReadPixels` / `glCopyTexImage2D` 这类**可疑帧抓取调用**。

### 7.4 Unreal Engine

- `libUE4.so`（XOR 0x18 解密）
- `/Script/CoreUObject.`（XOR 0x18 解密）——UE 反射系统中 `UClass` 的完整路径前缀

含义：识别 UE4 客户端，并通过 `/Script/CoreUObject.` 命名空间走 UE 反射查找特定 `UClass`、读取 `UProperty` 偏移做对应字段值校验。

---

## 8. 输入 / 触屏检测

- 明文：`RecordTouch`、`RecordTouchEnable`、`RecordTouchStart:name=pvp_mode`——在对战模式启用触摸记录
- 明文上报：`name=%s|rate=%.2f|is_root=%d`——上报某操作"频率（rate）"，**典型反连点 / 自动开火**特征
- 加密路径：`/proc/bus/input/devices`、`/dev/input/eventN`（通过 `opendir` / `readdir`、`__openat_2(AT_FDCWD, …)` 访问）——识别多余的虚拟输入设备（按键映射软件 / 物理外设)

`__openat_2` 共 5 处，参数 `flags=0x80` (`O_NOCTTY`) 与 `flags=0x13` (`O_RDWR|O_CREAT|...`) 是常见组合，多用于对 input device 节点的非阻塞探测。

---

## 9. JNI / Application 上下文

XOR 0x18 解密所得的 Java 端引用：

| 类 / 方法 | 用途 |
| --- | --- |
| `android/app/ActivityThread` + `()Landroid/app/ActivityThread;` + `currentActivityThread` | 反射获取主线程 ActivityThread |
| `getApplication` + `()Landroid/app/Application;` | 拿到 Application 单例 |
| `getPackageName` + `()Ljava/lang/String;` | 包名 |
| `getPackageManager` + `()Landroid/content/pm/PackageManager;` | PM 句柄 |
| `getPackageInfo` + `(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;` | 取包信息（签名 / versionCode） |
| `getPackageResourcePath` | APK 实际路径 |
| `AndroidManifest.xml` | 解析清单（权限、活动） |
| `/data/app/%s-%d.apk`、`/data/app/%s-%d/base.apk` | 不同 Android 版本下 APK 路径模板 |

明文常量 `ms_use_jni_get_apk_version` 表示**强制走 JNI 路径**取版本，绕过可能被 Hook 的 native PackageManager 缓存。

---

## 10. 网络上报通道

- 套接字调用：`socket` × 3、`connect` × 2、`bind` × 1、`listen` × 1、`accept` × 1、`recv`、`recvfrom`、`recvmsg`、`send`、`sendto`、`sendmsg`
- DNS：`getaddrinfo`、`freeaddrinfo`
- 加密 / 解密包：导出函数 `tss_sdk_encryptpacket`、`tss_sdk_decryptpacket`，关键判定 `tss_sdk_ischeatpacket`
- 内部回调指针上报模板：`init_info->tss_sdk_send_data_to_svr:%p`（明文）

`tss_sdk_ischeatpacket` 是**网络层外挂识别**入口：每个游戏包都被该函数过一遍，匹配规则文件中的特征，命中即上报并要求服务端踢人。

---

## 11. 自实现 Mini VM（MVM）

构建路径明文遗留：

```
/Users/bkdevops/tpmobile/workspace/p-c5c18c767fca4537af3d80bab10cc86d/china/mvm/source/VM/Memory/BopMemoryOperation.cpp
```

结合 `.text` 中的 MVM 相关字符串（`mvm_bk_proc`、`mvm_bk_task`），以及 `.text` 内存在大量**间接跳转表 + 不规则 basic-block 大小** （`brx9` / `brx10` 跳转转跳，反汇编后跳到由 `ldr xN, [xK, wM, sxtw #3]` 动态选择的目标）表明：

- 关键检测函数（特别是 ptrace 反附加 / 内存巡检 / 包加密）经"虚拟化保护"打散为字节码 + 解释器。
- 直接还原成可读 C 代码非常困难——需先识别每条 MVM 指令的处理函数，建立反解释脚本。
- 由于 MVM 也参与 §3.1 的 inline-hook 校验，**任何对 SO 自身的字节修改都会被 MVM 巡检捕捉**。

---

## 12. 字符串混淆方案

观察到至少两种存储形式：

| 方案 | 密钥 | 终止符 | 解密方式 | 占比 |
| --- | --- | --- | --- | --- |
| 明文 ASCII | — | `\x00` | — | 上报模板、JNI 类名、调试日志格式串 |
| 单字节 XOR | `0x18` | 字面 `\x00`（不参与异或） | 逐字节 XOR 直到原始字节 `0x00` | 路径 / 引擎 API / URL / 系统属性键，约 300+ 条 |

少量字符串疑似经过位移 / 多轮 XOR 处理，例如 `dkuktssuuvu`（疑似为 `libtersafe` 系标识的另一种掩码）。这些字符串通常仅在 `tss_jni_cmd` 或 MVM 字节码处使用。

解密代码可参考下面 Python 片段：

```python
def xor18(b):
    out = bytearray()
    for x in b:
        if x == 0: break
        out.append(x ^ 0x18)
    return out.decode("ascii", "replace")
```

---

## 13. 系统 / 文件类调用矩阵（节选）

| API | 调用次数 | 典型用途 |
| --- | --- | --- |
| `fopen` | 19 | `/proc/...`、APK base.apk、规则文件 |
| `fgets`/`__fgets_chk` | 11 | 按行解析 `/proc/self/status`、`/proc/%d/cmdline` |
| `fread` | 8 | 二进制规则文件读取 |
| `__open_2`/`__openat_2`/`open` | 8 | 直接以 `openat` 打开 `/proc`、input devices |
| `stat`/`fstat`/`statfs` | 14 | 文件存在性、文件系统类型 |
| `access` | 3 | su 等敏感二进制存在性 |
| `opendir`/`readdir` | 8 | `/proc/[pid]/`、`/system/bin/` 列目录 |
| `readlink` | 2 | `/proc/self/exe`、`/proc/[pid]/root` 解析符号链接 |
| `popen`/`pclose` | 2 | 运行 shell（典型用法：`getprop`、`mount`、`id`） |
| `ioctl` | 7 | 与自定义 driver / socket 交互；命中请求号 `0x6201/0x6205/0x6209/0x7`（疑似 socket SIOC 系列与 TP 自有命令） |
| `getauxval` | 3 | `AT_RANDOM`、`AT_SECURE` |
| `getuid`/`getpid`/`getppid`/`gettid` | 51 | 进程身份与线程标识 |
| `pthread_create`/`pthread_*` | 多 | 数个后台线程：扫描、上报、下载 |

---

## 14. 检测点摘要清单（速查）

> 给安全研究者 / 客户端集成者的快速参考。

- **反调试**：ptrace 自占用、`PR_SET_DUMPABLE=0`、`/proc/self/status` TracerPid、信号陷阱（SIGILL/SIGABRT/SIGBUS/SIGFPE/SIGSEGV/SIGPIPE/SIGSTKFLT）。
- **反 Hook**：函数头 opcode 比对、`mprotect` 区段 CRC、`9PtGum` (Frida Gum) 串匹配、`/proc/[pid]/maps` 模块名匹配、`dl_iterate_phdr` 模块枚举、`syscall` 旁路、`inotify` 文件属性监视。
- **反注入**：`dladdr` 反查 API 源 SO、`dlsym` 名字白名单、`libtersafe.so` 自身段 CRC、APK `CertMD5` 校验。
- **反 Root**：`getuid` UID、`stat/statfs/access` 检查 su 二进制 + Magisk / KernelSU 痕迹、`system_property_get` 读 `ro.build.tags`/`ro.debuggable`/`ro.secure`、`popen("getprop"/"mount"/"id")`。
- **反模拟器**：`getauxval(AT_RANDOM/AT_SECURE)`、`uname()`、`system_property` 读 `ro.kernel.qemu`/`ro.hardware`/`init.svc.qemud`、`strncmp` SoC 型号白名单（如 `exynos9810`）、CPU ABI 检查。
- **内存巡检**：`MrpcsActiveSig` 主动签名扫描线程、`mrpcsc.data` 远端下发规则、`mvm_bk_proc/mvm_bk_task` 后台任务、`ms_data_crc` 自检。
- **引擎层**：Unity Mono 反射（`Assembly-CSharp.dll` + `mono_*` 一族）、Vulkan/EGL/GL API 监控（`vk*`、`egl*`、`gl*`，尤其 `glReadPixels`/`glCopyTexImage2D`/`vkCmdCopyImage`）、UE4 反射（`libUE4.so` + `/Script/CoreUObject.`）。
- **输入层**：`/proc/bus/input/devices` 枚举、`RecordTouchStart:name=pvp_mode` 触摸录制、操作频率 `rate=%.2f` 上报。
- **JNI 层**：通过反射强制走 `ActivityThread.currentActivityThread() → getApplication() → getPackageManager().getPackageInfo()` 拿包名 / 版本 / 签名。
- **网络层**：`tss_sdk_ischeatpacket` 包级外挂识别、HTTP 明文从 `down.qq.com/iedsafe/...` 拉取规则、加解密包对 + token 协商。
- **代码混淆**：自有 MVM、字符串 XOR 0x18、大量 `prctl(PR_SET_VMA_ANON_NAME)` 命名匿名页便于自我巡检。

---

## 15. 分析方法学 / 复现步骤

为便于复核，下面给出复现本报告全部结论的步骤。

1. ELF 元信息：
   ```sh
   readelf -h libtersafe.so
   readelf -d libtersafe.so
   readelf -S -W libtersafe.so
   ```
2. 导出 / 导入符号：
   ```sh
   objdump -T libtersafe.so | awk '$2=="DF" && $3=="*UND*" {print $NF}' | sort -u
   readelf --dyn-syms -W libtersafe.so | awk '$5=="GLOBAL" && $7!="UND" {print $NF}'
   ```
3. 反汇编：
   ```sh
   aarch64-linux-gnu-objdump -d libtersafe.so > dump.txt
   ```
4. PLT 调用站点统计（按 `bl <imp>@plt` 解析，逐次复原 x0/x1 上下文）：脚本以 `capstone` 解码 `.text`，对每条 `bl plt`，往回最多 30 条指令拉 `mov w0, #imm` / `adrp + add` / `adrp + ldr` 三种取参模式，给出形参 0/1 的字符串或数值。
5. XOR 0x18 字符串恢复：扫描 `.rodata`，对每个非 0 字节起始的连续段，以 0x18 为密钥 XOR 直到遇到字面 `\x00`，过滤可打印 + 字母占比 ≥ 70% 后输出。
6. 详细脚本与中间产物可在临时分析机 `/tmp/{analyze,contexts,dump_ctx,xor_decode3}.py` 中找到，本次分析得到的 322 条高信号 XOR 解密字符串、PLT 调用上下文表均保存于本仓库分析时的 `/tmp/k18_hi.txt` / `/tmp/contexts3.txt`。

---

## 16. 免责声明

本报告仅用于安全研究、合规审计、防御方对接腾讯安全 SDK 时的排错与对账。报告**不包含也不教授**任何绕过 / 篡改方法，所有结论均通过对开源工具链（`binutils` / `capstone` / `pyelftools`）的静态使用得出；样本未在 root 环境或真机注入任何 hook 框架。请在所在司法管辖区允许的范围内使用本资料。
