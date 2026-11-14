# 验收要求 · 证明力追溯矩阵

**判据**：不信任第三方在不运行本仓库代码、不采信本机时钟的前提下，能复算同一结果并判错。本表是唯一验收依据；仓库内现行 `validation-*.json` 是内部观测记录，不作验收依据。测试全绿、生成文件、退出码 0、README 自称通过，均不构成验收。每行须有「若 X 改变，断言 Y 必然失败」；写不出的行必须删除，不得保留为声明。

## 一、证明力矩阵

| 外部依据 | 审查要素 | 工程断言／错误码 | 独立检验 | 证据文件 | 状态 |
|---|---|---|---|---|---|
| 证据规定 §93(一)(二)(三) | 系统环境完整可靠／正常运行／防错监测 | `doctor`、`verify_upstream`、`dependency_missing`／`dependency_mismatch` | `openssl dgst` 复算锁定源码并对照锁文件 | `upstream-lock.json`、`run.json.policy` | 已提供（仅锁定源码与依赖范围）；缺目标设备环境与清洁性 → 现场勘验／鉴定人补 |
| §93(四) | 完整保存、传输、提取，方法可靠 | `source_changed`、`copy_sha256_verified`、`test_frozen_snapshot_change_is_detected` | 逐文件 `openssl dgst` 比对 `private-source` 与 `private-snapshot` | `run.json.acquisition`、`source-manifest.json` | 已提供（所选字节）；缺采集前历史完整性 → 事前清单／原始载体补 |
| §93(五) | 正常往来活动中形成 | — | — | — | **缺失** → 举证方以原始设备、登录记录、对方自认补 |
| §93(六) | 保存／提取主体适当 | `capture_approval_required`、`identity_verified=false`、`account_identity=user_supplied_scope_not_independent_identity_proof` | 代码不能判定主体 | `run.json` | **缺失** → 授权书、公证／见证补 |
| §93(七) | 其他完整性与可靠性因素 | `cross_database_time_consistency_proven=false`、`cryptographic_database_log_pair_identity_proven=false` | 无 | `run.json` | 已标未知；缺多库同一时点 → 原子快照／鉴定补 |
| §94(二) 及公证规则 | 中立第三方平台确认；经公证内容应当确认真实性 | — | — | — | **缺失** → 公证机关／司法链平台补；公证的但书是「足以推翻」，门槛高于一般推定的「足以反驳」 |
| 在线诉讼规则 §16 | 上链后推定未经篡改 | 现有逐文件哈希 | 复算根哈希并与链上核验 | `source-manifest.json` | **前提缺失：尚未上链，不得援引该推定**；链上通常只存哈希，不得声称内容已上链 |
| §17 | 平台合规、无利害关系、系统清洁性、技术过程符合国标行标 | — | — | — | **缺失** → 存证平台资质材料补 |
| §18 来源 | 数据具体来源 | `source-manifest.json`、`source-reference.json`（源库／表／物理行） | `sqlite3 -readonly` 独立查询 | 两份回执 | 已提供（声明范围内） |
| §18 生成机制 | 生成机制 | `run.json`（`upstream_commit`、`policy`、`command`）＋锁文件 | `openssl dgst` 复算锁定源码 | `run.json`、`upstream-lock.json` | 已提供 |
| §18 存储过程 | 存储过程 | `run.json.acquisition`（前后哈希、复制窗口） | 逐文件复算 | `run.json` | 已提供（本机观测，非外部时间） |
| §18 公证／第三方见证 | 见证 | — | — | — | **缺失** → 公证机关／见证人补 |
| §18 关联印证 | 关联印证数据 | `source-audit.json`（三段对账） | 独立复算导出哈希与物理行 | `source-audit.json` | 部分提供；聊天外印证 → 举证方补 |
| 互联网法院规定 §11 第2款 | 可信时间戳／哈希值校验／区块链 | 哈希有；可信时间戳无 | 见 §二锚定契约 | `source-manifest.json` | 哈希已提供；**可信时间戳 pending**；技术本身不自动等于真实性，仍受第1款六项审查约束 |
| §11 第1款(四)(六) | 提取过程可重现／可通过特定形式验证 | 独立复算命令集（§五） | `openssl`／`sqlite3`／Node 重算 | — | 已提供（规格）；CLI 须按 §七 自检通过方计入 |
| 电子签名法 §8／PIPL §13 | 生成／存储方法、内容完整性、发件人鉴别；第三人信息处理合法基础 | — | — | — | **缺失** → 举证方依 §13 第（二）至（七）项说明合法性基础（并非一律需取同意）；§8 三项分别由方法说明、校验值、主体鉴别映射 |

## 二、外部时间锚契约

**观测值与锚定对象**：`moect_bridge.py:305,323,879,901,977,1071` 与 `normalize_export.py:637` 的 `datetime.now(timezone.utc)` 产生 `started_at`／`ended_at`／`created_at_utc`；现行 `validation-*.json` 的 `verified_at_utc`／`recorded_at_utc` 同源，一律 `local_observed_not_proof`、不得作签发时间。本机时钟可回拨，判定式不采信这些字段。锚定对象是现有 `source-manifest.json` 的 `files`（相对路径 → SHA-256）：外部复算者按 RFC 8785（JCS；Informational）规范化后求 SHA-256 得 `root`，不新增字段、文件、命令或令牌生成能力。

**令牌与状态（机器可判）**：外部 RFC 3161 TSA（Standards Track，2001-08，updated by RFC 5816）对 `root` 签发 `TimeStampToken`（CMS SignedData，`messageImprint` 即数据哈希，TSA 须使用可信时间源），或由公证／司法链出具核验凭证；令牌是外部产物，本技能不生成。`anchored = exists(token) ∧ verify_local(token, root, TSA_cert_chain) ∧ revocation_checked(CRL_or_equivalent) ∧ token.genTime ≥ observed_start`，否则恒为 `pending`。RFC 3161 全文未出现 "offline"：请求方须本地校验 TSA 签名、证书标识、`messageImprint` 与哈希算法 OID，证书撤销状态仍需 CRL 或等效外部数据，**不得写成「完全离线、无需任何外部数据」**；不得把 `pending` 写成已具备，不得把观测时钟写成签发时间，本机时钟回拨不改变该判定。

| 失败码 | 触发 | 定位到 |
|---|---|---|
| `anchor_absent` | 无可验签令牌 | 回执目录；状态 `pending` |
| `anchor_signature_invalid` | CMS 验签／证书链失败 | 令牌文件字节 |
| `anchor_root_mismatch` | `messageImprint` ≠ 外部复算 `root` | `source-manifest.json.files` 中差异键 |
| `anchor_revocation_unverifiable` | CRL／等效撤销数据不可得 | 证书链；状态 `pending` |
| `anchor_time_not_after_observation` | `genTime` 早于 `run.json.acquisition.started_at` | 两个时间字段 |

本机 `chat-evidence` 的 `anchor` 中 `trusted_timestamp.status="pending"`（"待接入可信时间戳服务"），不得当作已签发令牌。

## 三、入链前声明（不新增产物）

第 18 条五项由四份**现有**回执承载：来源 → `source-manifest.json`＋`source-reference.json`；生成机制 → `run.json`（锁定上游提交、策略、命令）；存储过程 → `run.json.acquisition`（复制前后哈希与窗口）；关联印证 → `source-audit.json`＋整理目录 `originals`；第三方见证与原始载体出示为矩阵中的缺失项。四份回执按固定导出哈希互相约束，转换件哈希不得冒充原数据库／原导出哈希。与本机 `chat-evidence` 的 `anchor` 对齐点仅为 `file_sha256`／`chain_sha256` 的复算口径，其时间戳仍为 `pending`。

## 四、条款级追溯与规程一致性

| 组 | SKILL.md 规程 | 断言／错误码 | 现有用例 | 证据文件 |
|---|---|---|---|---|
| G1 授权与范围 | 执行条件 1–3 | `capture_approval_required`、`declared_account_scope_conflict`、`windows_required` | `test_live_capture_requires_explicit_flag_before_any_output`、`test_bridge_declared_scope_conflict_rejects_records` | `run.json` |
| G2 环境与上游锁定 | 准备段 | `dependency_missing`／`dependency_mismatch`、固定源码哈希 | `test_doctor_validates_source_and_real_dependencies`、`test_verified_subset_and_original_unchanged` | `upstream-lock.json` |
| G3 原件／副本分离 | 提取段 | `source_changed`、`copy_sha256_verified` | `test_frozen_snapshot_change_is_detected`、`test_source_copy_rejects_linked_databases` | `run.json.acquisition` |
| G4 WAL 与提交边界 | 提取段 | `wal_invalid_or_unsupported` | `test_invalid_wal_is_rejected_before_any_output_is_created`、`test_known_whole_page_loss_is_stopped_by_prior_inventory` | `run.json.database_validation` |
| G5 身份与分组 | 整理段 | `identity_verified=false`、`conflicting_exported_account_ids` | `test_conflicting_known_owners_fail_entire_run_and_do_not_merge_messages`、`test_process_binding_rejects_wrong_user_and_unbound_directory` | `run.json`、`messages.jsonl` |
| G6 时间与三段对账 | 整理段 | `source_reconciliation_failed`、`exported_time_fields_mismatch` | `test_equal_total_cannot_hide_missing_and_extra_source_rows`、`test_saved_field_mutations_fail_even_when_source_locator_and_hash_match` | `source-reference.json`、`source-audit.json` |
| G7 附件与注入防护 | 整理段 | `invalid_attachment_path`、`linked_path_rejected` | `test_attachment_traversal_never_copies_external_bytes`、`test_chat_markup_is_escaped_and_never_executed` | `attachment_index.jsonl`、`issues.jsonl` |
| G8 失败与恢复 | 验收段 | `partial/1`、`failed/2` | `test_existing_output_unchanged`、`test_actual_cancel_keeps_original_and_marks_incomplete` | `manifest.json`、`run.json` |

**一致性检查（机器可判）**：把 SKILL.md 每条「必须／不得／不能」映射到 G1–G8 与 §一矩阵；任一禁令无对应断言编号即 `unmapped_invariant` 失败。其余必测边界并入各组：固定源码逐文件相符、输入输出不重叠且不覆盖、原生 ID 精度、原时间／时区／展示分离、附件逃逸与 reparse、HTML 转义与 CSV 公式防护、重复键与非有限数拒绝、网络／子进程／密钥限制、输出冲突与恢复对账；相同数量但丢一条加一条、改正文或解释标签不能通过。ISO/IEC 27037:2012（识别／收集／获取／保全）、27041:2015（方法适用性 "fit for purpose"）、NIST CFTT（需求 → 测试断言 → 用例 → 结果）、SQLite `fileformat` WAL §4.1／4.2／4.5 用作设计与追溯框架；均为指南或分散文档，**不作符合性或认证声称**，出处见 §六。

## 五、独立复算与可证伪集

不新增脚本或用例；外部验证者在产物目录执行，结果不依赖本仓库代码：

```text
openssl dgst -sha256 private-source/*.db private-source/*.db-wal
node -e "const fs=require('fs'),c=require('crypto');const o=JSON.parse(fs.readFileSync('source-manifest.json','utf8'));const s=v=>Array.isArray(v)?'['+v.map(s).join(',')+']':v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+s(v[k])).join(',')+'}':JSON.stringify(v);console.log(c.createHash('sha256').update(s(o.files)).digest('hex'))"
sqlite3 -readonly private-snapshot/session.db "PRAGMA integrity_check;"
```

`openssl`（C 实现）与 Python `hashlib` 对同一字节须一致：本机实测 `SKILL.md` 同为 `bb9360ed0458ddba7505fe8fbf68ca203ca0686d2b1c6d1cb5d5b94801dab8c1`。第二语言为 Node.js（V8）：RFC 8785 的序列化语义取自 ECMA-262（键按 UTF-16 code units 递归排序、I-JSON 子集、无 NaN／Infinity、Unicode 原样、不输出空白），Node 比 Python 更贴合该 RFC；本机实测 Node 规范化与 Python `json.dumps(sort_keys=True)` 对 `upstream-lock.json` 同得 `0d10dea125b17cd3a0a90f7dd130073349ae2adb9f9252201d37897739949d81`，但该对象只含整数与字符串，含浮点数时以 ECMAScript 数字语义为准。`jq -S -cj` 在 I-JSON 子集且无尾随换行时与该规范化同哈希，但键排序按 UTF-8 字节而非 UTF-16 code units：对 `{"😀":1,"\uE000":2}`，JCS 得 😀 在前、`jq -S` 得 `\uE000` 在前，故 `jq -S` 不得冒充 JCS。确定性打包：固定排序、规范换行、不写入运行时间；Merkle 根由排序后的叶子哈希两两拼接求得，复算者按同一规则独立计算。`PRAGMA integrity_check` 只做数据库逻辑一致性检查（表／索引／记录／freelist／约束），**不是 WAL 文件字节级完整性校验**，且不含外键检查。

| 攻击面 | 若 X 改变 | 必然失败／状态 |
|---|---|---|
| 时钟回拨 | 改 `started_at`／`created_at_utc`／`verified_at_utc` 为任意过去值 | **无现有断言失败 → 缺失**；外部锚定判定不采信本机时钟，`anchor_absent` 仍为 `pending`。不得宣称已防护 |
| 清单事后重写 | 事后增删／替换 `source-manifest.json.files` | `test_observed_manifest_does_not_claim_prior_inventory_verification`、`test_known_missing_shard_is_rejected_before_row_accounting`、`test_known_whole_page_loss_is_stopped_by_prior_inventory` |
| 原件替换 | 改 `private-source` 任一字节 | `source_changed`、`test_frozen_snapshot_change_is_detected`、`test_wrong_hash_writes_no_source` |
| 时间锚伪造 | 放置不可验签或摘要不符的令牌 | `anchor_signature_invalid`／`anchor_root_mismatch`（外部检验，非仓库断言） |
| 账号归属冒认 | 改 `account_id`／`account_scope`／显示名 | `declared_account_scope_conflict`、`test_conflicting_known_owners_fail_entire_run_and_do_not_merge_messages`；身份真实性仍 `identity_verified=false` → **归属由举证方补** |

## 六、外部依据出处

| 依据 | 出处 | 类别／版本状态 |
|---|---|---|
| 证据规定 §93 七因素、§94 五项推定及公证规则 | https://www.court.gov.cn/fabu/xiangqing/212721.html | 最高法官网全文；法释〔2019〕19号，2020-05-01 施行，现行有效 |
| 在线诉讼规则 §16–§19 | https://www.court.gov.cn/fabu/xiangqing/309551.html | 最高法官网全文；法释〔2021〕12号，2021-08-01 施行 |
| 《在线诉讼规则》理解与适用（推定仅及上链后、上链前审查、链上只存哈希） | https://www.court.gov.cn/zixun/xiangqing/309561.html | 最高法官方释义全文 |
| 互联网法院规定 §11 第1款六项审查、第2款四项技术、第3款专家与鉴定 | https://www.court.gov.cn/zixun/xiangqing/116981.html | 最高法官网全文；法释〔2018〕16号，2018-09-07 施行 |
| 微信记录不予采信反例：无原始载体／身份未证（吉林丰满法院〔2024〕吉0211民初974号）；须演示登录、证明对方为微信号使用者、保证完整性（鹤岗工农法院） | https://zh.wikisource.org/zh-hant/吉林省吉林市丰满区人民法院（2024）吉0211民初974号民事判决书 ；http://hggn.hljcourt.gov.cn/public/detail.php?id=5416 | 裁判文书第三方转录（非裁判文书网原站，需登录）＋法院官网文章；**均非原站直连核对** |
| ISO/IEC 27037:2012、27041:2015 | https://www.iso.org/standard/44381.html ；https://www.iso.org/standard/44405.html | 官方目录页与摘要；27037 经 2018 复审确认现行；27041 现行状态待复核（页面显示 90.60 与 2026 新一轮复审）；**全文均未取得，不作条款级断言** |
| NIST CFTT | https://www.nist.gov/itl/csd/secure-systems-and-applications/computer-forensics-tool-testing-program-cftt ；Mobile Device Spec V3.2 (2024-02) https://www.nist.gov/system/files/documents/2024/02/01/Mobile%20Device%20Forensic%20Tool%20Test%20Specification%20V%203.2.pdf | 概览页＋正式 specification；**无单一「通用方法论」编号文档**，方法分散于 specification／test assertions／NISTIR；V3.2 全文未逐页核对 |
| RFC 3161、RFC 8785 | https://www.rfc-editor.org/rfc/rfc3161 ；https://www.rfc-editor.org/rfc/rfc8785 | 全文；3161 为 Standards Track (2001-08)、updated by RFC 5816、全文无 "offline"；8785 为 Informational (2020-06)、非 IETF 标准轨道 |
| SQLite WAL §4.1／4.2／4.5、`integrity_check` | https://www.sqlite.org/fileformat.html#the_write_ahead_log ；https://www.sqlite.org/pragma.html#pragma_integrity_check | 官方文档全文；WAL magic 为 `0x377f0682`／`0x377f0683`、校验和为连续 Fibonacci 加权、读取须以 mxFrame 固定快照；integrity_check 不含外键且不校验 WAL 字节 |
| 电子签名法 §8、个人信息保护法 §13 | https://www.gov.cn/govweb/gongbao/content/2004/content_62978.htm ；http://www.npc.gov.cn/npc/c2/c30834/202108/t20210820_313088.html | 官方全文；电子签名法 2004 公报本（2019 修正本未从 npc.gov.cn 直取）；PIPL 2021-11-01 施行，npc.gov.cn 页未直连抓取，建议二次核对 |
| Moect v1.2.8 固定提交与源码锚点 | https://github.com/mofan6/Moect/commit/88dffc7d0d06632f8061b0a19aa82b38337d7ee5 | tag／commit／Release（含 SHA256SUMS.txt）公开可得；实现为单文件 `core/data.py`／`core/exporting.py` 而非同名目录；**源码正文未读，不作实现层断言** |

## 七、适用边界与机器可判失效条件

- `raw_bytes_not_available`：授权范围内只读检查未取得微信原始库字节与 WAL/SHM/journal；所有字节级结论仅为 SQLite 格式级，非本机实测，不得绕过既有目录授权读取。`moect_source_unread`：固定提交源码正文未读，§四 中对 `core.data`／`core.exporting` 的引用仅为模块名，不含实现层结论。
- `tzdata_missing`：缺 IANA 时区数据 → `test_normalize_export.py:294` 断言 `'not_checked' != 'match'`、`test_normalize_export.py:283` 断言 `'success' != 'partial'` 失败。`psutil_missing`：缺 `psutil` → `test_independent_bridge.py:162`、`test_moect_bridge.py:120` 报 `ModuleNotFoundError`。
- `approval_order_mismatch`：`test_independent_bridge.py:123` 期望 `capture_approval_required`，实得 `path_invalid`（路径校验先于 `moect_bridge.py:946` 的授权检查）。`upstream_unset`：未设 `MOECT_TEST_UPSTREAM` → 48 项跳过，不得宣称完整验收。
- `tool_unavailable`：§五任一独立 CLI（`openssl`／`sqlite3`／Node）缺失、官方校验值不符或只读自检未返回 `ok`，对应检验不计入复算结果；独立 CLI 二进制须与官方发布校验值一致方可使用，`jq -S` 仅为键排序对照、不等价于 JCS，缺失不构成验收缺口。`rfc3161_offline_claim`：不得把本地校验写成「标准明示完全离线」，证书撤销状态仍需 CRL。`anchor_pending`：无可验签令牌不得写成已具备；`validation_json_internal`：现行验证记录为内部观测。
- 本机独立复跑（2026-11-14）：系统 Python 3.13.12 未用固定 venv → 161 用例 3 失败、2 错误、48 跳过，根因是缺 `psutil` 与 IANA 时区数据，未改断言或预期值；按固定 venv＋`MOECT_TEST_UPSTREAM` 复跑 → 154 用例 OK、13 跳过，属内部观测、不作验收依据。真实材料试点与确切微信版本验收仍未执行 → `raw_bytes_not_available`、`anchor_pending`。

## 八、真实试点

Windows 部署须先在该环境跑合成验证；`path.stat` 与句柄 `fstat` 的 ctime 含义可能不同，跨 API 对齐文件身份、大小、mtime 与创建时间，不能删 ctime 检查掩盖误报。准备器核对 ZIP 原始成员名（不只 Windows 规范化后的名称）；测试库显式关闭；符号链接权限不足只标该用例未测、不提权。在授权目标机完成一单聊、一群聊试点，全范围程序对账，抽核不少于 30 条（不足全查）覆盖实际存在的类型；未解释的正文、身份、时间差异不能通过。机器可判门槛：现场记录确切微信版本及进程／账号目录绑定证据，缺则 `version_unverified`；无 `capture` 回执为 `capture_not_run`；抽核条数或类型覆盖不足为 `sampling_incomplete`；任一成立即不得写「真实试点通过」。使用合成账号、聊天、数据库作测试，不提交真实资料、密钥、身份映射或敏感日志；真实用户反馈与机器测试分别记录。
