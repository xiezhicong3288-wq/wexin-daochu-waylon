# 执行命令

所有示例路径、账号和会话都是占位值。先从当前已授权任务确定实际值，不照抄占位符、不猜账号。路径必须为绝对路径。运行 Python 3.11+；Windows 运行组件与材料均位于技能目录之外。

## 一次性准备

仅在允许下载和安装依赖时联网；准备过程不访问聊天。

```powershell
python "<技能目录>\scripts\prepare_runtime.py" --destination "C:\已确认目录\moect-runtime-0.1.0" --download --install-deps
```

目标目录必须不存在、父目录已存在。源码逐文件校验后才保存到 `source`；独立环境为 `venv`。已有官方源代码 ZIP 时使用 `--archive "C:\...\Moect-source.zip"` 代替 `--download`。没有 `--install-deps` 时不安装依赖。准备失败保留 `setup-status.json`，重做用新目录，不删除旧记录绕过保护。

核对实际结果后，后续命令使用准备好的 `venv\Scripts\python.exe`（非 Windows 为 `venv/bin/python`）。程序不会自动下载 Python 或提升权限。

0.2.1 沿用相同 Moect 源码和四项核心依赖，Windows 额外固定 `tzdata==2026.6`。已有运行目录先核对 `doctor`；Windows 缺该时区包时，在该运行目录的独立环境中安装新版 `requirements-runtime.txt`，不更换上游，不必重装或改名。非 Windows 平台的依赖集合保持原样。

没有可用 Python 时，先准备已授权的独立解释器，不把 WindowsApps 别名当作可用安装。本次 Windows 使用官方 NuGet 的固定 Python 3.13.17 包，在任务私有目录校验目录服务的包哈希与解释器签名后运行；未改系统 PATH、执行策略或全局 Python。该实测版本不自动替代其他已验证的 Python 3.11+ 环境。

## 运行组件检查

```powershell
& "<运行环境Python>" "<技能目录>\scripts\moect_bridge.py" --upstream "<运行目录>\source" doctor
```

PowerShell 中直接执行带引号的可执行路径时，在命令前使用调用运算符 `&`。示例中的占位内容需要替换；可先运行脚本 `--help`。

## 已解密快照

```powershell
& "<运行环境Python>" "<技能目录>\scripts\moect_bridge.py" --upstream "<运行目录>\source" sessions --source "<已解密快照>" --account-id "<wxid>" --account-scope "<已确认范围标签>" --output "<新会话目录输出>"
```

会话目录只保存在本机，默认不把联系人列表输出到云端。账号ID和范围标签是操作范围，不是实名核验。

```powershell
& "<运行环境Python>" "<技能目录>\scripts\moect_bridge.py" --upstream "<运行目录>\source" export --source "<已解密快照>" --account-id "<wxid>" --account-scope "<已确认范围标签>" --session "<会话ID>" --format json --output "<全新导出目录>"
```

`--session` 可重复。可显式给 `--start`/`--end` Unix秒范围。需要已授权本机媒体时给 `--local-media`，否则资源按跳过处理；不会联网补下载。

有事前采集清单时增加 `--source-manifest "<事前清单JSON>"`。清单格式为 `{"schema_version":1,"files":{"session.db":"<SHA256>","message_0.db":"<SHA256>"}}`，必须实际列全本次范围的数据库及存在的 WAL/SHM/journal；不能照抄示例，或把发现缺失后的清单冒充事前清单。也兼容原审查的纯相对路径/哈希映射。清单差异保存在本机 `run.json.error_details`。

原始字节保存在 `private-source`，SQLite 只读取单独的 `private-snapshot`。实际原件清单为 `source-manifest.json`；独立源行参考为 `source-reference.json`；导出落盘对账为 `source-audit.json`。没有事前清单时回执标记 `observed_only`，不证明此前未知的缺失。桥接器 `completed/0`、`partial/1`、`failed/2` 分开；语义不确定或冲突不能被数量通过掩盖。

## 当前 Windows 账号的小范围试点

先由只读核查取得程序身份和实际PID，与已授权账号范围对应；不能把这里的旗标当作授权本身。

```powershell
& "<运行环境Python>" "<技能目录>\scripts\moect_bridge.py" --upstream "<运行目录>\source" capture --account-dir "<已确认账号目录>" --account-id "<wxid>" --account-scope "<已确认范围标签>" --pid <已验证PID> --process-exe "<已验证微信程序绝对路径>" --process-sha256 "<实际SHA256>" --process-start-time <实际进程创建时间> --session "<会话ID>" --format json --output "<全新试点目录>" --live-read-approved
```

`--scan-timeout` 不得超过60秒。进程与账号目录关系、用户身份、程序哈希或创建时间不匹配时停止，不自动提权或扫描其他进程。不支持的输入或缺失权限不能以放松检查解决。Windows 实机未完成验收时仍标记为试点。

`capture` 同样支持 `--source-manifest`，对应加密源文件清单。验证冻结输入后才解密同一份字节，不再由上游另行复制 live 文件。WAL 校验只证明实际存储字节的规则匹配；目标写入器不匹配时停止。旧世代盐值尾帧目前保守拒绝。第一页密钥校验不等于全部页 HMAC 或库/日志密码学关联已验证；跨库共同时间点没有自动保证。

## 中立整理

```powershell
python "<技能目录>\scripts\normalize_export.py" --input "<Moect导出JSON或JSONL>" --account-scope "<同一范围标签>" --out "<全新中立整理目录>"
```

可重复 `--input`。普通JSON上限256MiB；更大材料用JSONL，单行上限16MiB。上限或格式异常会明确停止/记录，不能删消息凑兼容。

`manifest.json` 及进程退出码同时判断：success/0、partial/1、failed/2。失败目录即使含原件副本及部分索引也不能进入后续分析。中立索引不是 `wechat-evidence-expert` 的直接输入；后续用途确定后再按其现行 schema 显式适配。

## 核对最终整理去向

有数据库来源时，使用导出任务产生的独立参考核对最终整理文件。普通文本的独立解码包含 ZSTD，因此使用原固定依赖环境；JSON-only 整理器本身仍只需标准库。

```powershell
& "<运行环境Python>" "<技能目录>\scripts\source_audit.py" --reference "<导出目录>\source-reference.json" --normalized "<中立整理目录>\messages.jsonl" --out "<中立整理目录>\source-reconciliation.json"
```

报告文件必须不存在，父目录须为已建好的本机私有目录。保留整理目录中的 `originals`，用于核对固定导出哈希、每个顶层/嵌入位置及父子关系。JSON/JSONL 是这条整理链的输入；HTML 导出仍可单独核对来源，不伪装成整理器输入。

退出码 `0` 表示声明范围的对账通过，`1` 表示独立解释仍有未完成项，`2` 表示失败。最后对照桥接器、整理器、最终核对三份回执；其中任何一项失败或部分完成，都不能以另一个步骤通过代替。复杂消息的可读展示不作通用语义认证，原始字段须精确保留；真实类型、附件和上下文仍需本机抽核。

## 合成测试

使用已准备的固定依赖环境，并明确提供锁定源码目录：

```powershell
$env:MOECT_TEST_UPSTREAM = "<运行目录>\source"
& "<运行环境Python>" -m unittest discover -s "<技能目录>\scripts\tests" -v
```

非 Windows 使用同名环境变量与 `venv/bin/python`。未提供 `MOECT_TEST_UPSTREAM` 时部分真实 core 测试会跳过，不能据此宣称完整验收。不得改用真实微信目录当测试夹具。

先验输入与账号范围，再调用工具。工具返回只取脱敏状态和计数，完整结果留在本机材料目录。
