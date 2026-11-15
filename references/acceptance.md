# 验收要求 · 证明力追溯矩阵

**判据**：不信任第三方在不运行本仓库代码、不采信本机时钟、目录名、文件数量、内部观测与历史汇报的前提下，能复算同一结果并判错。本表是唯一验收依据；内部观测、本机实测、测试全绿、生成文件、退出码 0、README 自称通过、commit message、历史汇报与仓库内 `validation-*.json`，均不构成验收。每行须有「若 X 改变，断言 Y 必然失败」并定位到文件／字节／断言编号／退出码；写不出的行必须删除，不得保留为声明。

## 一、证明力矩阵

| 外部依据 | 审查要素 | 工程断言／错误码 | 独立检验 | 证据文件 | 状态 |
|---|---|---|---|---|---|
| 证据规定 §93(一)(二)(三) | 系统环境完整可靠／正常运行／防错监测 | `doctor`、`verify_upstream`、`dependency_missing`／`dependency_mismatch` | `openssl dgst` 复算锁定源码并对照锁文件 | `upstream-lock.json`、`run.json.policy` | 已提供（仅锁定源码与依赖范围）· G2；缺目标设备环境与清洁性不作断言 |
| §93(四) | 完整保存、传输、提取，方法可靠 | `source_changed`、`copy_sha256_verified`、`test_frozen_snapshot_change_is_detected` | 逐文件 `openssl dgst` 比对 `private-source` 与 `private-snapshot` | `run.json.acquisition`、`source-manifest.json` | 已提供（所选字节）· G3；采集前历史完整性不在断言内 |
| §93(六) | 保存／提取主体适当 | `capture_approval_required`、`identity_verified=false`、`account_identity=user_supplied_scope_not_independent_identity_proof` | 代码不能判定主体；把 `identity_verified` 写成 true 则 G5 用例失败 | `run.json` | 主体由举证方以授权书／公证补 · G1/G5；无外部凭证即 `unmapped_invariant` |
| 在线诉讼规则 §16 | 上链后推定未经篡改（原文但书「有相反证据足以推翻的除外」） | 现有逐文件哈希 | 复算根哈希并与链上核验 | `source-manifest.json` | 前提缺失：尚未上链 · G6；若声称已上链，`anchor_absent` 与 `openssl ts -verify` 非 0 即判错 |
| §18 来源 | 数据具体来源 | `source-manifest.json`、`source-reference.json`（源库／表／物理行） | `sqlite3 -readonly` 独立查询；无原始库即 `source_reference_absent` | 两份回执 | 已提供（声明范围内）· G6 |
| §18 生成机制 | 生成机制 | `run.json`（`upstream_commit`、`policy`、`command`）＋锁文件 | `openssl dgst` 复算锁定源码 | `run.json`、`upstream-lock.json` | 已提供 · G2 |
| §18 存储过程 | 存储过程 | `run.json.acquisition`（前后哈希、复制窗口） | 逐文件复算 | `run.json` | 已提供（本机观测，非外部时间）· G3 |
| §18 关联印证 | 关联印证数据 | `source-audit.json`（三段对账） | 独立复算导出哈希与物理行 | `source-audit.json` | 部分提供 · G6；聊天外印证不在断言内 |
| 互联网法院规定 §11 第2款 | 电子签名／可信时间戳／哈希值校验／区块链等技术手段或存证平台认证，能够证明真实性的应当确认 | 仅哈希；电子签名、可信时间戳、平台认证均无 | 见 §二锚定契约 | `source-manifest.json` | 仅哈希 · G6；时间戳 `pending`；原文未设「须先受第1款六项审查」条件 |
| §11 第1款(四)(六) | 提取过程可重现／可通过特定形式验证 | 独立复算命令集（§五） | `openssl`／`sqlite3`／Node 重算 | — | 已提供（规格）· G6/G8；CLI 未纳入完整性锚见 §七 |

## 二、外部时间锚契约

**观测值与锚定对象**：`moect_bridge.py:305,323,879,901,977,1071` 与 `normalize_export.py:637` 的 `datetime.now(timezone.utc)` 产生 `started_at`／`ended_at`／`created_at_utc`，一律 `local_observed_not_proof`、不得作签发时间，本机时钟可回拨。锚定对象是现有 `source-manifest.json` 的 `files`（相对路径 → SHA-256）：外部复算者须先按 RFC 8785 §3.1 与 RFC 7493 确认输入属 I-JSON 子集，不满足即拒绝、不得计算 `root`，再按 §3.2 序列化求 SHA-256 得 `root`；该子集内 §五 `s()` 的输出与 JCS 一致（数字、字符串与 UTF-16 键序已按 §3.2.2／§3.2.3 官方向量复算），但 `s()` 本身不是合规 JCS 实现，输入违规时其根哈希无效（见 §五 四个可判错输入）。无 `root` 可锚定时 `anchor_pending` 恒真。

**令牌与状态（机器可判）**：外部 RFC 3161 TSA（Standards Track，2001-08，updated by RFC 5816）对 `root` 签发 `TimeStampToken`（CMS SignedData，`messageImprint` 即数据哈希），或由公证／司法链出具核验凭证；令牌是外部产物，本技能不生成。`anchored = exists(token) ∧ verify_local(token, root, TSA_cert_chain) ∧ revocation_checked(CRL_or_equivalent) ∧ timeliness_checked(nonce_or_local_trusted_ref)`，否则恒为 `pending`。RFC 3161 §2.4.2 要求以本地可信时间参考或 nonce 验证时效性：本机 `started_at` 已被判为观测值、非 local trusted time reference，不得作不等式右端；回拨本机时钟不影响该判定。同节要求检查 TSA 证书撤销状态，故不得写成「完全离线、无需任何外部数据」。**负对照**：以非 `root` 摘要或不可验签令牌调用 `openssl ts -verify`，退出码非 0 才证明契约能拒绝伪造；签发成功或验签通过本身不构成 `anchored`。

| 失败码 | 触发 | 定位到 |
|---|---|---|
| `anchor_absent` | 无可验签令牌 | 回执目录；状态 `pending` |
| `anchor_signature_invalid` | CMS 验签／证书链失败 | 令牌文件字节 |
| `anchor_root_mismatch` | `messageImprint` ≠ 外部复算 `root` | `source-manifest.json.files` 中差异键 |
| `anchor_revocation_unverifiable` | CRL／等效撤销数据不可得 | 证书链；状态 `pending` |
| `timeliness_unverifiable` | nonce 不符且无本地可信时间参考 | 请求／令牌 nonce 字段；`openssl ts -verify` 退出码非 0 |

## 三、入链前声明（不新增产物）

第 18 条第二款六项（具体来源、生成机制、存储过程、公证机构公证、第三方见证、关联印证数据）中，四份**现有**回执仅承载前三项与末项：来源 → `source-manifest.json`＋`source-reference.json`；生成机制 → `run.json`（锁定上游提交、策略、命令）；存储过程 → `run.json.acquisition`（复制前后哈希与窗口）；关联印证 → `source-audit.json`＋整理目录 `originals`。公证机构公证与第三方见证不在回执内，不得代称具备；无原始库时 `source_reference_absent`。四份回执按固定导出哈希互相约束，转换件哈希不得冒充原数据库／原导出哈希。§93(五)、§94 第一款(二)、§17 四项与 §18 第二款公证／第三方见证均无工程断言，按判据不列 §一，由举证方／存证平台补；不得写成已验收。

## 四、条款级追溯与规程一致性

| 组 | SKILL.md 规程 | 断言／错误码 | 现有用例 | 证据文件 |
|---|---|---|---|---|
| G1 授权与范围 | 执行条件 1–3（含三方对账与原生备份禁令） | `capture_approval_required`、`declared_account_scope_conflict`、`windows_required`、`object_identity_unproven`／`native_backup_not_restorable`（仅规程层，无代码用例） | `test_live_capture_requires_explicit_flag_before_any_output`、`test_bridge_declared_scope_conflict_rejects_records` | `run.json` |
| G2 环境与上游锁定 | 准备段 | `dependency_missing`／`dependency_mismatch`、固定源码哈希 | `test_doctor_validates_source_and_real_dependencies`、`test_verified_subset_and_original_unchanged` | `upstream-lock.json` |
| G3 原件／副本分离 | 提取段 | `source_changed`、`copy_sha256_verified` | `test_frozen_snapshot_change_is_detected`、`test_source_copy_rejects_linked_databases` | `run.json.acquisition` |
| G4 WAL 与提交边界 | 提取段 | `wal_invalid_or_unsupported` | `test_invalid_wal_is_rejected_before_any_output_is_created`、`test_known_whole_page_loss_is_stopped_by_prior_inventory` | `run.json.database_validation` |
| G5 身份与分组 | 整理段 | `identity_verified=false`、`conflicting_exported_account_ids` | `test_conflicting_known_owners_fail_entire_run_and_do_not_merge_messages`、`test_process_binding_rejects_wrong_user_and_unbound_directory` | `run.json`、`messages.jsonl` |
| G6 时间与三段对账 | 整理段 | `source_reconciliation_failed`、`exported_time_fields_mismatch` | `test_equal_total_cannot_hide_missing_and_extra_source_rows`、`test_saved_field_mutations_fail_even_when_source_locator_and_hash_match` | `source-reference.json`、`source-audit.json` |
| G7 附件与注入防护 | 整理段 | `invalid_attachment_path`、`linked_path_rejected`、`attachment_reported_incomplete`／`message_resources_incomplete_or_skipped`（状态须在 `archive.html` 可见） | `test_attachment_traversal_never_copies_external_bytes`、`test_chat_markup_is_escaped_and_never_executed`、`test_html_discloses_upstream_resource_status_even_when_bytes_copied` | `attachment_index.jsonl`、`issues.jsonl`、`archive.html` |
| G8 失败与恢复 | 验收段 | `partial/1`、`failed/2` | `test_existing_output_unchanged`、`test_actual_cancel_keeps_original_and_marks_incomplete` | `manifest.json`、`run.json` |

**一致性检查（机器可判）**：§一 每行外部条款须经「工程断言 → G1–G8 与 §四 用例 → §五 独立复算 → 证据文件 → 状态」闭环；SKILL.md 每条「必须／不得／不能」须映射到 G 组与断言编号；任一禁令或外部条款无对应断言编号即 `unmapped_invariant` 失败。执行条件 3 的两条新禁令映射 G1／G3 与 §五 两个攻击面，但代码不产生该码、无对应用例，故标 `unmapped_invariant`，不得计入已验收，由 §七 交接点与用户交回的还原凭证判错。其余必测边界并入各组：固定源码逐文件相符、输入输出不重叠且不覆盖、原生 ID 精度、原时间／时区／展示分离、附件逃逸与 reparse、HTML 转义与 CSV 公式防护、附件／消息媒体状态在 `archive.html` 可见、重复键与非有限数拒绝、网络／子进程／密钥限制、输出冲突与恢复对账；相同数量但丢一条加一条、改正文或解释标签不能通过。SQLite `fileformat` WAL §4.1／4.2／4.5 仅作字节级设计与追溯框架，不作符合性或认证声称，出处见 §六。

## 五、独立复算与可证伪集

命令集在 `moect_bridge.py export`／`capture` 的会话产物目录执行，结果不依赖本仓库代码；仅 `normalize_export.py` 产物时没有 `source-manifest.json`／`private-snapshot`，不得套用本节命令，结论限于整理保真（见 README）。§七 对象同一性未成立时不得套用本节，也不得开始整理。不新增脚本或用例。

```text
openssl dgst -sha256 private-source/*.db private-source/*.db-wal
node -e "const fs=require('fs'),c=require('crypto');const o=JSON.parse(fs.readFileSync('source-manifest.json','utf8'));const s=v=>Array.isArray(v)?'['+v.map(s).join(',')+']':v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+s(v[k])).join(',')+'}':JSON.stringify(v);console.log(c.createHash('sha256').update(s(o.files)).digest('hex'))"
sqlite3 -readonly private-snapshot/session.db "PRAGMA integrity_check;"
```

`openssl`（C 实现）与 Python `hashlib` 对同一字节须一致。第二语言为 Node.js（V8）：§五 的 `s()` 对 RFC 8785 §3.2.2 官方数字与字符串样例可得一致序列化，键按 `Object.keys().sort()` 即 UTF-16 code units 排序（§3.2.3）；Appendix B 是 IEEE 754 数字序列化样例，不是排序向量。**但 `s()` 不是合规 JCS 实现**：RFC 8785 §3.1 要求输入适配 I-JSON（RFC 7493 §2.1 禁 surrogate／noncharacter、§2.3 禁重复名），§3.2.2.2 要求 lone surrogate MUST terminate with an appropriate error，§3.2.2.3 要求 NaN／Infinity 同样终止；`s()` 反而静默输出转义串、把 NaN／Infinity 变 `null`、由 `JSON.parse` 吞掉重复键、把超精度整数舍入。可判错检验：以 `{"x":"\ud800"}`、`{"x":NaN}`、`{"a":1,"a":2}` 与 `s({x:2**53+1})` 分别调用 `s()`，若其未终止报错而返回结果（末例的整数已被舍入），根哈希不得声称按 RFC 8785 规范化。`jq -S -cj` 在 I-JSON 子集且无尾随换行时与 `s()` 同哈希，但键排序按 UTF-8 字节：对 `{"😀":1,"\uE000":2}`，JCS 得 😀 在前、`jq -S` 得 `\uE000` 在前，故 `jq -S` 不得冒充 JCS。确定性打包：固定排序、规范换行、不写入运行时间；Merkle 根由排序后的叶子哈希两两拼接求得。`PRAGMA integrity_check` 只做数据库逻辑一致性检查（表／索引／记录／freelist／约束），**不是 WAL 文件字节级完整性校验**，且不含外键检查。

| 攻击面 | 若 X 改变 | 必然失败／状态与定位 |
|---|---|---|
| 时钟回拨 | 改 `started_at`／`created_at_utc` 为任意过去值 | 断言 `anchored` 必然不成立；`anchor_absent` 仍 `pending`、`timeliness_unverifiable` 由 `openssl ts -verify` 退出码非 0 判错；定位 RFC 3161 §2.4.2 不以该字段为基准 |
| 清单事后重写 | 事后增删／替换 `source-manifest.json.files` | `test_observed_manifest_does_not_claim_prior_inventory_verification`、`test_known_missing_shard_is_rejected_before_row_accounting`、`test_known_whole_page_loss_is_stopped_by_prior_inventory`；定位到清单差异键 |
| 原件替换 | 改 `private-source` 任一字节 | `source_changed`、`test_frozen_snapshot_change_is_detected`、`test_wrong_hash_writes_no_source`；定位到 `openssl dgst -sha256` 差异字节 |
| 时间锚伪造 | 放置不可验签或摘要不符的令牌 | 断言 `anchored` 必然不成立；`anchor_signature_invalid`／`anchor_root_mismatch`，`openssl ts -verify` 退出码非 0，定位到 `messageImprint` 字节 |
| 账号归属冒认 | 改 `account_id`／`account_scope`／显示名 | `declared_account_scope_conflict`、`test_conflicting_known_owners_fail_entire_run_and_do_not_merge_messages`；身份仍 `identity_verified=false`，归属由举证方补 |
| 复算工具链替换 | 替换 `sqlite3.exe`／`jq.exe`／TSA CA 为任意其它二进制 | 断言「工具链已锚定」必然不成立 → `toolchain_unanchored`；定位：`git cat-file -p HEAD:references/upstream-lock.json` 的 `files` 键不含这些路径，退出码 0 也不改变判定 |
| 安装位内容变更 | 改活跃工作树任一文件 | 断言「加载内容已锚定」必然不成立 → `install_mutable`；定位：`fsutil reparsepoint query` 标签 `0xa0000003` 指向工作树，`git cat-file -p HEAD` 对象不变 |
| I-JSON 违规输入 | 在 `source-manifest.json.files` 放 lone surrogate／重复键／NaN／超精度整数 | 断言「根哈希按 RFC 8785 规范化」必然不成立；定位：RFC 8785 §3.2.2.2／§3.2.2.3 要求终止报错而 `s()` 不终止，见本节四个可判错输入 |
| 对象同一性冒认 | 以目录名、文件数量或历史汇报代替三方对账 | 断言「目标目录即该会话」必然不成立 → `object_identity_unproven`；定位：§七 两字符十六进制目录计数 1、`tar_index.dat` 前 4 字节 `524d4648`，第三方无法从字节复算出会话 ID |
| 原生备份伪装输入 | 把 `RMFH`／`.dat`／`.enc` 改名或包装成 JSON/JSONL／`.db` 喂入整理或导出段 | 断言「输入属三类允许形态」必然不成立 → `native_backup_not_restorable`；定位：§七 5 个 `.dat` 头 16 字节、0 个 `SQLite format 3\x00`，仅 SKILL.md 执行条件 3 与 G1／G3 禁令可判错，代码不产生该码 |

## 六、外部依据出处

| 依据 | 出处 | 原文可取得性／核对状态 |
|---|---|---|
| 证据规定 §93 七因素、§94 五项推定及第2款公证但书 | https://www.court.gov.cn/fabu/xiangqing/212721.html | 官网全文 200；已逐条核对 §93(一)–(七)、§94(一)–(五)，第一款但书「足以反驳」、第2款「足以推翻」；法释〔2019〕19号，2020-05-01 施行 |
| 在线诉讼规则 §16–§18 | https://www.court.gov.cn/fabu/xiangqing/309551.html | 官网全文 200；已逐条核对 §16 但书、§17 四项、§18 第二款六项（具体来源、生成机制、存储过程、公证机构公证、第三方见证、关联印证数据）；法释〔2021〕12号，2021-08-01 施行 |
| 互联网法院规定 §11 第1款六项、第2款技术手段或存证平台认证、第3款专家与鉴定 | https://www.court.gov.cn/zixun/xiangqing/116981.html | 官网全文 200；已逐条核对第1款(一)–(六)、第2款、第3款；原文无「第2款四项技术」或「须先受第1款六项审查」表述，不得作条款级断言；法释〔2018〕16号 |
| RFC 3161 §2.4.2、RFC 8785 §3.1／§3.2.2.2／§3.2.2.3／§3.2.3／Appendix B、RFC 7493 §2.1／§2.3 | https://www.rfc-editor.org/rfc/rfc3161.txt ；https://www.rfc-editor.org/rfc/rfc8785.txt ；https://www.rfc-editor.org/rfc/rfc7493.txt | 全文 `.txt` 直连 200（54,585／41,879／12,849 字节），已核对条款原文；不带 `.txt` 的 `/rfc/rfcNNNN` 实测 301 至 `/info/rfcNNNN/` 索引页，不得据此称全文。3161 为 Standards Track (2001-08)、updated by RFC 5816；8785 为 Informational (2020-06)，Appendix B 为数字序列化样例、排序规则在 §3.2.3；7493 为 I-JSON 约束 |
| SQLite WAL §4.1／4.2／4.5、`integrity_check` | https://www.sqlite.org/fileformat.html#the_write_ahead_log ；https://www.sqlite.org/pragma.html#pragma_integrity_check | 官方文档全文 200；WAL magic 为 `0x377f0682`／`0x377f0683`、校验和为连续 Fibonacci 加权、读取须以 mxFrame 固定快照；integrity_check 不含外键且不校验 WAL 字节；仅作设计框架，不作符合性声称 |
| Moect v1.2.8 固定提交与 Release 校验清单 | https://github.com/mofan6/Moect/commit/88dffc7d0d06632f8061b0a19aa82b38337d7ee5 ；https://github.com/mofan6/Moect/releases/download/v1.2.8/SHA256SUMS.txt | 固定提交源码正文（64 个文件逐文件校验，见 `upstream-lock.json`）与 Release `SHA256SUMS.txt` 全文可取；不作实现层推断 |
| 电子签名法 §8、个人信息保护法 §13 | https://www.gov.cn/govweb/gongbao/content/2004/content_62978.htm ；http://www.npc.gov.cn/npc/c2/c30834/202108/t20210820_313088.html | **未取得原文／未逐页核对**：本次未取全文，不得作条款级断言，§一 不列对应行；由举证方另附官方全文后重核 |

## 七、适用边界与机器可判失效条件

**适用边界与对象同一性（A）**：授权范围内未取得微信原始库字节与 WAL/SHM/journal，字节级结论仅为 SQLite 格式级；真机 capture、真实材料抽核与对真实 `root` 签发的令牌均未产生。边界不是验收结论，不得据此宣称通过。目标目录（两字符十六进制名，**不是会话 ID**）内 5 个 `.dat`：3 个 `RMFH` 头（133,241／109,499／272 字节）、`detail.dat` 7 字节、`pkg_info.dat` 249 字节；0 个 `SQLite format 3\x00`、0 个 `.db`。父目录计数：725 个 `@chatroom` 分片目录、3124 个其它目录、1 个两字符十六进制目录、2 个根级文件（`pkg.attr` 258 字节、`tar_index.dat` 10,686,596 字节，均 `RMFH` 头）。三方对账「目录名 ↔ 会话 ID ↔ 客户端原始显示」仅第一项可观测；唯一可能承载映射的私有索引 `tar_index.dat` 无公开格式规范，不得据字节推断；第三项未取得。故 `object_identity_unproven` 成立 → **不能整理**，且 `native_backup_not_restorable`：`RMFH`／`ChatPackage`／`Index`／`Media`／`.enc` 不得自动恢复、解密或覆盖，不读、不复制、不上传备份中的聊天正文。交接点：由用户在本机微信完成还原，交回客户端原始显示、微信自带还原结果与目录名↔会话 ID 对应凭证，本技能不生成、不代称；目录名、文件数量、内部观测、历史汇报或复述会话标识均不构成对账。定位到字节：改 `tar_index.dat` 前 4 字节或上述计数而无第三方可核对映射，`object_identity_unproven` 必然成立；把 `.dat` 当输入则 `native_backup_not_restorable` 必然成立。外部复算：用 `openssl dgst -sha256` 对所列元信息文件独立求哈希，并只读比对头 16 字节；不运行本仓库代码，不是 §五 会话产物命令集，也不生成 `root`。

**边界与不可得清单（C）**：成员身份归属 → 举证方补授权书／本机通讯录原始显示 → `account_identity=user_supplied_scope_not_independent_identity_proof`；发言人与账号标识映射 → 用户补客户端原始显示 → `speaker_mapping_absent`；撤回与系统消息 → 用户补微信自带还原结果 → `timeline_incomplete`；缺号与时间线连续性 → 用户补连续还原件与独立源行参考 → `source_reference_absent`；多备份合并 → 用户逐份还原并交回清单 → `multi_backup_merge_unproven`；两个不同账号标识的关联 → 举证方补且不得推断 → `account_linkage_unproven`。六项任一缺失即不得写「记录完整」；「导出成功」不得写成「记录完整」。

- `tzdata_missing`／`psutil_missing`／`approval_order_mismatch`／`upstream_unset`：删 IANA 时区数据 → `test_normalize_export.py:294` 断言 `'not_checked' != 'match'`、`:283` 断言 `'success' != 'partial'` 失败；删 `psutil` → `test_independent_bridge.py:162`、`test_moect_bridge.py:120` 报 `ModuleNotFoundError`；`test_independent_bridge.py:123` 期望 `capture_approval_required`，路径校验（`moect_bridge.py:946`）先于授权检查；未设 `MOECT_TEST_UPSTREAM` 时真实 core 用例跳过，不得宣称完整验收。定位到断言编号与退出码非 0。
- `object_identity_unproven`／`native_backup_not_restorable`／`source_reference_absent`／`toolchain_unanchored`／`install_mutable`／`commit_unsigned`：三方对账缺任一、把原生备份当输入、无原始库却声称有独立源行参考，三项任一成立即不得开始整理；`git cat-file -p HEAD:references/upstream-lock.json` 的 `files` 仅 64 个 Moect 源文件，不含 `sqlite3.exe`／`jq.exe`／TSA CA／CRL；`fsutil reparsepoint query` 返回 `0xa0000003` 且指向活跃工作树；`git log --format=%G?` 返回 `N`。判错检验：三者任一改变（工具入锁／安装位改不可变快照／提交签名生效）本行即失效。在此之前，替换任一复算工具或工作树文件，仓库无断言失败，**不得宣称工具链、加载内容、提交对象或对象同一性已锚定**。
- `tool_unavailable`／`anchor_pending`：§五 任一 CLI 缺失或 `sqlite3 -readonly "PRAGMA integrity_check;"` 未返回 `ok`，对应检验不计入复算；无对 `source-manifest.json.files` 之 `root` 签发且可验签的令牌，`anchored` 判定式不成立，恒为 `pending`。

## 八、真实试点

进入本段前须先满足 §七 三方对账，否则 `object_identity_unproven`，不得开始整理。Windows 部署须先在该环境跑合成验证；`path.stat` 与句柄 `fstat` 的 ctime 含义可能不同，跨 API 对齐文件身份、大小、mtime 与创建时间，不能删 ctime 检查掩盖误报。准备器核对 ZIP 原始成员名（不只 Windows 规范化后的名称）；测试库显式关闭；符号链接权限不足只标该用例未测、不提权。在授权目标机完成一单聊、一群聊试点，全范围程序对账，抽核按约定不少于 30 条（不足全查）覆盖实际存在的类型，该阈值是约定值、非统计抽样保证；未解释的正文、身份、时间差异不能通过。机器可判门槛：现场记录确切微信版本及进程／账号目录绑定证据，缺则 `version_unverified`；无 `capture` 回执为 `capture_not_run`；抽核条数或类型覆盖不足为 `sampling_incomplete`；任一成立即不得写「真实试点通过」。使用合成账号、聊天、数据库作测试，不提交真实资料、密钥、身份映射或敏感日志；真实用户反馈与机器测试分别记录。
