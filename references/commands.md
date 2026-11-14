# 执行命令

路径、账号、会话均为占位值，先由已授权任务确定实际值；一律用绝对路径，Python 3.11+，运行组件与材料位于技能目录之外。回执字段的证明力、锚定状态与失效条件一律见 [验收要求](acceptance.md)。

## 一次性准备

```powershell
python "<技能目录>\scripts\prepare_runtime.py" --destination "<已确认目录>\moect-runtime" --download --install-deps
```

目标目录须不存在、父目录已存在；已有官方源码 ZIP 用 `--archive` 代替 `--download`。源码逐文件校验通过才写入 `source`，独立环境为 `venv`；准备失败保留 `setup-status.json`，重做用新目录。准备器不启动 Moect、不登录、不读取聊天、不执行压缩包内容。后续命令用 `venv\Scripts\python.exe`（非 Windows 为 `venv/bin/python`），先跑 `doctor`；Windows 缺 IANA 时区规则时在原独立环境补装固定依赖，不换上游、不改全局 Python。

## 运行组件检查

```powershell
& "<运行环境Python>" "<技能目录>\scripts\moect_bridge.py" --upstream "<运行目录>\source" doctor
```

PowerShell 中执行带引号的可执行路径须在命令前用 `&`；可先运行脚本 `--help`。

## 已解密快照

```powershell
& "<运行环境Python>" "<技能目录>\scripts\moect_bridge.py" --upstream "<运行目录>\source" sessions --source "<已解密快照>" --account-id "<wxid>" --account-scope "<范围>" --output "<新会话目录>"
```

```powershell
& "<运行环境Python>" "<技能目录>\scripts\moect_bridge.py" --upstream "<运行目录>\source" export --source "<已解密快照>" --account-id "<wxid>" --account-scope "<范围>" --session "<会话ID>" --format json --output "<全新导出目录>" [--source-manifest "<事前清单JSON>"]
```

`--session` 可重复；`--start`/`--end` 为 Unix 秒；`--local-media` 仅在已授权本机媒体时给出。清单形状为 `{"schema_version":1,"files":{"session.db":"<SHA256>"}}`，必须事前列全本次范围的数据库及 WAL/SHM/journal，不得事后补写冒充事前清单；差异写入 `run.json.error_details`。原件字节存 `private-source`，SQLite 只读 `private-snapshot`；`source-manifest.json`、`source-reference.json`、`source-audit.json`、`run.json` 的字段语义见验收矩阵。无事前清单时标 `observed_only`。`completed/0`、`partial/1`、`failed/2` 分别判断。

## 授权 Windows 小范围试点

先由只读核查取得程序身份与实际 PID，与已授权账号范围对应；旗标不是授权本身。

```powershell
& "<运行环境Python>" "<技能目录>\scripts\moect_bridge.py" --upstream "<运行目录>\source" capture --account-dir "<账号目录>" --account-id "<wxid>" --account-scope "<范围>" --pid <已验证PID> --process-exe "<程序绝对路径>" --process-sha256 "<实际SHA256>" --process-start-time <实际创建时间> --session "<会话ID>" --format json --output "<全新试点目录>" --live-read-approved
```

`--scan-timeout` 不超过 60 秒。进程与账号目录关系、用户身份、程序哈希或创建时间不匹配即停止，不提权、不扫描其他进程。解密前校验冻结 WAL 的头部、盐值、累计校验与提交边界；第一页密钥校验不等于全页 HMAC 或库/日志密码学关联，跨库共同时间点未自动保证。

## 中立整理

```powershell
python "<技能目录>\scripts\normalize_export.py" --input "<Moect导出JSON或JSONL>" --account-scope "<同一范围>" --out "<全新目录>"
```

`--input` 可重复；普通 JSON 上限 256 MiB，JSONL 单行 16 MiB，超限明确停止，不删消息凑兼容。`manifest.json` 与退出码同时判断：success/0、partial/1、failed/2；失败目录即使含部分索引也不得进入后续分析。中立索引不是证据技能的原生输入，后续适配须读其现行 schema 显式转换。

## 核对最终整理去向

```powershell
& "<运行环境Python>" "<技能目录>\scripts\source_audit.py" --reference "<导出目录>\source-reference.json" --normalized "<整理目录>\messages.jsonl" --out "<整理目录>\source-reconciliation.json"
```

报告文件须不存在，父目录须为已建好的本机私有目录；保留 `originals` 以核对固定导出哈希、顶层/嵌入位置与父子关系。退出码 0/1/2 分别为通过、独立解释仍有未完成项、失败。桥接器、整理器、最终核对三份回执须分别通过，任一失败或部分完成不得由另一份通过代替。

## 合成验证

```powershell
$env:MOECT_TEST_UPSTREAM = "<运行目录>\source"
& "<运行环境Python>" -m unittest discover -s "<技能目录>\scripts\tests" -v
```

未提供 `MOECT_TEST_UPSTREAM` 时真实 core 用例会跳过，不得据此宣称完整验收；不得用真实微信目录当测试夹具。结果只取脱敏状态与计数，完整产物留在本机材料目录。独立复算命令、锚定契约与可证伪条件见 [验收要求](acceptance.md)。
