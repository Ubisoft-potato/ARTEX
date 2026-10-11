---
name: rea-reverse-engineering
description: 用本机 `rea`（rea-agents，npx 调用）做逆向分析：APK/IPA、.NET/PE 元数据、JS/Electron 应用、固件、ADB 设备取证、原生二进制反汇编/反编译（需配置 Ghidra）。用户提到反编译、逆向、APK 分析、固件提取、ADB 取证、.NET/PE 分析、JS 应用还原时使用。
---

# REA 逆向分析（rea-agents）

**前提：目标已获授权测试/分析。** REA 是一个命令行逆向工具集合，100+ 子命令覆盖 Android/iOS/
JS-Electron/.NET-PE/固件/ADB 设备/原生二进制等逆向场景，部分能力需要外部分析引擎（Ghidra/Hopper/IDA）
配合，另一部分（Android、.NET/PE 元数据、JS 静态分析、ADB、固件提取、通用容器解包）**不需要任何引擎**，
开箱可用。

---

## 调用方式

本机未把 `rea` 装到全局 PATH，统一用 `npx rea-agents <command> [args] [options]`：

```bash
npx --yes rea-agents doctor                     # 每次任务开始先跑一次，看哪些能力可用
npx --yes rea-agents <command> --help           # 查看某子命令参数
npx --yes rea-agents <command> --schema         # 查看该子命令的 JSON Schema（比猜参数更准）
npx --yes rea-agents <command> ... --format json  # 机器可读输出，便于后续解析/登记
```

**不要凭记忆拼参数**——命令多达 100+，上面两条 `--help`/`--schema` 是获取准确参数的权威来源，
每次用新命令前先查一次。

---

## 本机环境现状（跑 `rea doctor` 得到）

| 检查项 | 状态 | 说明 |
|---|---|---|
| host | ⚠️ unsupported_host（kali 2026.3） | REA 官方只测过 macOS/Ubuntu/Fedora/Arch 系，Kali 不在列表但多数非引擎能力仍可跑，遇到怪异报错先怀疑是这个 |
| Hopper | ❌ 未配置 | **Mac 专用**，Linux 上不可用，忽略 doctor 里关于它的提示 |
| Ghidra | ❌ 未配置（`GHIDRA_INSTALL_DIR` 未设置） | 原生二进制反汇编/反编译（`decompile`/`function`/`xrefs`/`inspect-native-*`/`trace-native-*` 等）**依赖它**，没配置这些命令会直接失败 |
| IDA | ❌ 未配置 | 可选，走 `REA_IDA_MCP_CONFIG` 对接已运行的 IDA MCP，一般不需要 |

**要跑原生二进制（ELF/Mach-O/PE 可执行文件）的反汇编/反编译**，需要先装好 Ghidra 12.1.x 并设置
`GHIDRA_INSTALL_DIR` 指向解压目录，再重新跑 `rea doctor` 确认 `ghidra: ok`。没有这一步，下面
「原生二进制」分组的命令都不可用——先用 `rea doctor` 确认，不要盲目尝试再报错排查半天。

---

## 不需要引擎、开箱可用的能力分组

| 场景 | 关键命令 |
|---|---|
| **通用容器/未知文件** | `inspect-artifact`（先摸底，告诉你下一步该用哪个命令）、`extract-artifact`（安全解包） |
| **Android (APK)** | `inspect-android-package`（声明+manifest）、`decode-android-resources`（apktool 解码）、`inspect-android-class`/`inspect-android-method`（类/方法级反编译）、`search-android-classes`、`trace-android-references` |
| **.NET / PE（托管程序集）** | `inspect-managed-artifact`（身份识别）、`inspect-managed-members`（元数据成员/签名/CIL）、`inspect-managed-native-boundaries`（PInvoke 边界）、`compare-managed-members` |
| **JS / Electron 应用** | `analyze-javascript-application`（静态还原）、`recover-javascript-sources`（还原可读源码+溯源）、`export-web-scripts`、`inspect-electron-page`、`compare-javascript-export-shapes` |
| **网页/浏览器运行时（需本机或远程 CDP 调试端口）** | `inspect-web-page`、`capture-browser-scenario`、`capture-web-screenshot`、`inspect-web-network-capture`、`discover-webmcp-tools`、`observe-web-session`/`observe-web-execution` |
| **固件** | `extract-firmware`（按签名提取分区/文件）、`inspect-firmware-regions`（先探测签名，不解包） |
| **ADB 设备取证**（需 `adb` 可见设备） | `list-adb-devices`、`inspect-adb-package`、`pull-adb-package`（带 SHA-256）、`read-adb-logcat`、`list-adb-packages`、`resolve-adb-packages` |
| **PE 资源 / plist / Keyed Archive** | `inspect-pe-resources`、`inspect-plist`、`inspect-keyed-archive` |

## 需要 Ghidra（本机未配置，先 `rea doctor` 确认 `ghidra: ok` 再用）

`analyze`（原生程序）、`decompile`、`function`、`instructions`、`xrefs`、`search`、`trace`、
`read-bytes`、`inspect-native-api`、`inspect-native-instruction`、`inspect-native-data-type`、
`resolve-native-call-targets`、`trace-native-values`、`inspect-binary-layout`、
`annotate-native-function`、`address-to-file-offset`。

---

## 典型工作流

### 1. APK 快速侦察（不需要引擎）

```bash
npx --yes rea-agents inspect-android-package /path/app.apk --format json
npx --yes rea-agents decode-android-resources /path/app.apk --format json
npx --yes rea-agents search-android-classes /path/app.apk --query "<关键字>" --format json
npx --yes rea-agents inspect-android-method /path/app.apk --class <类名> --method <方法名> --format json
```

### 2. 原生二进制（先确认 Ghidra 就位）

```bash
npx --yes rea-agents doctor --format json   # 确认 ghidra.ok == true，否则先装 Ghidra 设 GHIDRA_INSTALL_DIR
npx --yes rea-agents analyze /path/to/binary --format json
npx --yes rea-agents decompile /path/to/binary --procedure main --format json
npx --yes rea-agents xrefs /path/to/binary <address> --format json
```

### 3. JS/Electron 应用还原

```bash
npx --yes rea-agents analyze-javascript-application /path/to/app --format json
npx --yes rea-agents recover-javascript-sources /path/to/app --out <输出目录> --format json
```

### 4. ADB 设备上的 App 取证

```bash
npx --yes rea-agents list-adb-devices --format json
npx --yes rea-agents resolve-adb-packages <设备序列号> --query <包名关键字> --format json
npx --yes rea-agents pull-adb-package <设备序列号> --package <包名> --out <输出目录> --format json
npx --yes rea-agents inspect-android-package <拉到本地的apk路径> --format json
```

### 5. 固件提取

```bash
npx --yes rea-agents inspect-firmware-regions /path/firmware.bin --format json   # 先看有哪些签名候选
npx --yes rea-agents extract-firmware /path/firmware.bin --out <输出目录> --format json
```

---

## 与 ARTEX 的对接（可选，非必须）

REA 本身不读写 ARTEX 的资产库/漏洞库——它是独立的逆向 CLI。逆向过程中若发现**安全相关的确认性
问题**（硬编码密钥/凭据、不安全加密实现、调试后门、越权逻辑等），按 ARTEX 既有流程用
`report_finding` 登记：`vulnclass` 填具体类别（如 `hardcoded-credential`/`insecure-crypto`），
`evidence` 填反编译/反汇编输出片段（`rea` 的 `--format json` 输出可直接摘录相关字段），
`asset_ids` 如适用关联对应的 `app`/`service` 资产（先用 `insert_assets` 登记该 APK/固件对应的
`app` 资产，再在 `report_finding` 里引用其 id）。纯逆向还原（无安全结论）不必强行往资产/漏洞库塞。

---
