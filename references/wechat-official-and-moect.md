# 微信官方路径与文件兼容性

核验日 2026-11-19（北京时间）。微信产品路径适用于中国大陆微信。操作前记录账号范围、源和目标设备、操作系统及微信版本，按实际界面选择范围。官方指引可随客户端调整。

## 客户端渠道与版本

| 平台 | 核验时可见版本 | 来源 |
| --- | --- | --- |
| Windows | 腾讯软件中心列正式版 4.2.0.53，标注 2026-11-17。 | [腾讯软件中心微信页面](https://pc.qq.com/detail/8/detail_11488.html) |
| macOS | 中国区 App Store 列 4.2.0，标注 2026-11-16。 | [微信 Mac App Store 页面](https://apps.apple.com/cn/app/id836500024)、[Apple 中国区查询](https://itunes.apple.com/lookup?id=836500024&country=cn) |
| iOS | 中国区 App Store 列 8.0.80，标注 2026-10-23。 | [微信 iOS App Store 页面](https://apps.apple.com/cn/app/id414478124)、[Apple 中国区查询](https://itunes.apple.com/lookup?id=414478124&country=cn) |
| Android | 腾讯应用宝页面显示 8.0.79，腾讯下载域另有命名为 8.0.80 的 ARM64 下载对象。应用宝的发布日期和该对象的可得性分别记录。 | [腾讯应用宝微信页面](https://sj.qq.com/appdetail/com.tencent.mm)、[腾讯下载 CDN](https://dldir1v6.qq.com/weixin/android/weixin8080android3220_0x28005032_arm64.apk) |

以上是公开分发渠道观测。实际设备版本以微信界面或系统元数据为准，功能是否出现仍按账号、灰度范围与客户端界面核对。运行组件和真机试点使用独立的版本证据，详见下文和 [验收要求](acceptance.md)。

本轮未在 Windows 微信 4.2.0.53 上运行桥接或验证媒体取回。Moect Issue #15 报告的是不同构建 4.2.0.13 和 Moect 1.2.8，三张历史群聊图片在微信内可另存，在该次 Moect 样本中未取回。将此个案用于列举媒体缺项并回查客户端。 [Moect Issue #15](https://github.com/mofan6/Moect/issues/15)

## 按目标选择路径

| 目标 | 路径与交接物 | 来源 |
| --- | --- | --- |
| 换手机或平板 | iOS／安卓旧设备进入「我 → 设置 → 聊天记录管理 → 导入与导出 → 导出到另一台手机或平板」。鸿蒙进入「我 → 设置 → 通用 → 聊天记录迁移与备份 → 迁移 → 迁移到另一台手机或平板」。设备连到同一网络，由目标设备登录并扫码。记录所选会话和目标客户端实际显示。 | [腾讯客服：迁移手机微信聊天记录](https://kf.qq.com/touch/wxappfaq/180122ua6NB7180122zI3AZR.html) |
| 在电脑微信查看手机会话 | 移动端「导入与导出」中选择「导出到电脑」，电脑微信确认接收后，记录合并到电脑微信客户端供查看。核对同一账号及同一网络。该路径来自终端厂商支持说明，供核对现场功能。 | [华为终端官方支持说明](https://consumer.huawei.com/cn/support/content/zh-cn01118496/) |
| 用手机备份到外置存储 | 腾讯客服注明微信 iOS 8.0.59 起支持，安卓 8.0.64 起灰度开放。接入 U 盘或移动硬盘后，从「聊天记录管理 → 备份与恢复 → 新增一个备份 → 存储位置」选择外部存储设备，可选全部、指定会话或指定时段。备份包由微信加密保存，所属账号可在客户端恢复，恢复时去重并合并现有记录。 | [腾讯客服：手机外置备份与恢复](https://kf.qq.com/touch/sappfaq/250623juqArE250623n2E7VJ.html)、[iOS 操作步骤](https://kf.qq.com/faq/2510217f2e22251021FJ3y6b.html) |
| 用 Windows 微信备份或恢复手机聊天 | 在电脑版微信「更多 → 迁移与备份 → 备份与恢复」选择方向，设备连到同一网络，由用户在手机上选范围或确认。恢复会与手机中现有记录合并。涉及留存或举证，先记录源和目标当前状态，再另存客户端结果并记录变更。 | [腾讯客服《怎么使用微信 for Windows聊天记录备份恢复》](https://kf.qq.com/faq/161224mmmUju161224A3UVrE.html) |
| 将旧 Windows 电脑的微信聊天迁至新电脑 | 先核对两端微信版本和同一账号。官方对 2.6.3–3.9.12 与 4.0.0 起的目录命名和导入方式分别说明。3.x 与 4.x 并存时按官方步骤在客户端导入。旧 `WeChat Files` 与新 `xwechat_files` 是不同目录，不把前者放入后者。 | [腾讯客服：旧电脑迁移至新电脑](https://kf.qq.com/faq/190425ZFBzqa190425ZNNzQv.html)、[腾讯客服：升级至 4.0 及以上常见问题](https://kf.qq.com/faq/250710MraIZj250710QniyAr.html) |
| 使用 Mac 微信和 iPhone 备份或迁移 | App Store 编辑指南介绍 Mac 微信侧边栏的「迁移与备份」。其中「迁移」将 Mac 聊天复制到 iPhone，「备份与恢复」可将手机聊天备份到 Mac 后再还原到手机。以实际客户端显示为准。 | [中国区 App Store 编辑指南](https://apps.apple.com/cn/mac/story/id1760592883) |
| 获取自己的微信个人信息副本 | 「我 → 设置 → 个人信息与权限 → 个人信息浏览与导出 → 导出个人信息」，副本发至用户指定邮箱。将收到的副本作为单独材料保存并按实际内容记录范围。 | [《微信隐私保护指引》§5.1.10](https://oper.my-qcloud.com/readtemplate?lang=zh_CN&t=weixin_agreement&s=privacy) |
| 整理已导出的会话文件 | 使用有明确来源的 Moect 会话 JSON/JSONL 和相邻资源目录。检查 `manifest.json` 的来源、会话标识、筛选条件及演示标记；按 [执行命令](commands.md) 将文件整理到新的私有目录。 | [Moect v1.3.0 源码：会话文件写入](https://github.com/mofan6/Moect/blob/7498e9f21ab283edb55a5d6a2e17c7ad696cf168/core/exporting.py#L203-L227) |

《微信隐私保护指引》于 2026-08-17 更新并生效。§1.35 说明聊天记录在终端设备上保存，用户可以自行备份、删除或跨设备转移。§1.11 的「导入与导出聊天记录（手机/平板）」描述设备连接功能。腾讯客服也将换机迁移与本地保存、备份关联。查阅的公开官方材料未确认个人信息副本包含会话全文，也未提供读取个人会话全文的通用导出 API。 [《微信隐私保护指引》](https://oper.my-qcloud.com/readtemplate?lang=zh_CN&t=weixin_agreement&s=privacy)、[腾讯客服《微信聊天记录保存规则说明》](https://kf.qq.com/faq/161224feeE3I161224MrMvqY.html)

收到 `ChatPackage`、`Index`、`Media`、`.enc` 或含 `RMFH` 标记的原生备份时，走 [验收要求 §七](acceptance.md#七适用边界与机器可判失效条件) 的客户端还原交接。记录原设备、账号、备份批次、目的设备、客户端还原结果及所选会话对应关系。文件夹名称和时间只作为观察值。官方备份包、个人信息副本、聊天界面留存和 Moect 文件分别登记来源。

公开官方资料说明备份和恢复过程及个人信息副本的入口。`RMFH` 和目录名取自既有本地观察，腾讯公开资料未提供通用文件签名或个人信息副本结构。使用 [输入预检](commands.md#输入预检) 时，此类标记只触发核对来源和客户端交接。个人信息副本按官方邮件来源单独登记，`--source-kind` 表示操作者已核对的来源声明。

腾讯客服说明，重装或删除后，如果事先没有迁移或备份，无法从微信服务器恢复已删除的聊天记录。先核对仍能查看记录的设备以及已有迁移、备份的实际范围。 [腾讯客服：恢复删除的微信聊天记录](https://kf.qq.com/faq/161224FjQR3u1612247BNzia.html)

Windows 4.x 升级导入或搜索索引建立期间，聊天显示和搜索覆盖可能暂时不同。保留旧数据，在客户端确认导入结束后再按会话和日期抽核。官方说明导入可优先使用硬链接，同盘的新旧目录需核实底层文件关系后才可当作独立留存。 [腾讯客服：升级至 4.0 及以上常见问题](https://kf.qq.com/faq/250710MraIZj250710QniyAr.html)

第三方工具的本机处理须分别核对设备、账号与会话的授权，以及适用法律和腾讯软件协议。协议 §8.2.1 对运行中数据复制、未经授权的第三方自动读取与规避技术措施设有约束，并载明法律允许或腾讯书面许可的例外。官方备份和迁移由用户在微信客户端完成。 [《腾讯微信软件许可及服务协议》§8.2.1.4、§8.2.1.6、§8.2.1.7](https://oper.my-qcloud.com/cgi-bin/readtemplate?lang=zh_CN&t=weixin_agreement)

## Moect 版本与会话文件

- 上游最新正式发布为 v1.3.0，北京时间 2026-11-15，提交 `7498e9f21ab283edb55a5d6a2e17c7ad696cf168`。上游标注 Windows 10 1809+、Windows 11 x64 和 GPL-3.0。技能的运行组件由 [源码锁](upstream-lock.json) 固定在 v1.2.8。v1.3.0 的媒体、数据读取、缓存和新增模块变化需要单独验证运行兼容性。 [v1.3.0 Release](https://github.com/mofan6/Moect/releases/tag/v1.3.0)、[上游更新说明](https://github.com/mofan6/Moect/blob/7498e9f21ab283edb55a5d6a2e17c7ad696cf168/docs/release-1.3.0.md)、[源码版本比较](https://github.com/mofan6/Moect/compare/v1.2.8...v1.3.0)
- 会话 JSON 外层为 `{metadata,messages,count}`。会话 JSONL 首行为单独的 `{metadata}`，后续为消息行，无尾部计数。`metadata` 声明会话 ID、显示名、版本、`Asia/Shanghai`、`filters`、`export_options` 和 `demo`。整理器按字段结构识别输入，时间和筛选字段按导出声明记录，`demo:true` 只作演示或测试材料。资源路径相对于会话文件，合并转发、引用和可见资源状态分别核对。 [元数据](https://github.com/mofan6/Moect/blob/7498e9f21ab283edb55a5d6a2e17c7ad696cf168/core/exporting.py#L149-L161)、[写入格式](https://github.com/mofan6/Moect/blob/7498e9f21ab283edb55a5d6a2e17c7ad696cf168/core/exporting.py#L203-L227)
- v1.3.0 改善群邀请、撤回、拍一拍和历史群记录的呈现，并在能识别时用 `extra.game_emoji` 保留骰子或猜拳结果，资源仍取决于输入中的可用引用与本地文件。跨版本显示文本有变化时，根据导出版本、筛选、消息标识和媒体状态回源核对。上游会递归移除 `content`、`packed_hex` 和下划线开头的内部字段。这里保留的是导出件字节与字段，原始客户端状态仍回源核对。 [上游更新说明](https://github.com/mofan6/Moect/blob/7498e9f21ab283edb55a5d6a2e17c7ad696cf168/docs/release-1.3.0.md)、[表情处理](https://github.com/mofan6/Moect/blob/7498e9f21ab283edb55a5d6a2e17c7ad696cf168/core/resources.py#L433-L451)、[字段清理](https://github.com/mofan6/Moect/blob/7498e9f21ab283edb55a5d6a2e17c7ad696cf168/core/exporting.py#L43-L47)
- 新增的收藏导出使用独立的 `category: "favorites"`／`items` 结构。收藏、朋友圈、表情包任务和 HTML 等展示格式在会话整理入口之外，保留原材料和实际来源。Moect 的内置游戏表情图属于腾讯或相关权利人。 [收藏导出结构](https://github.com/mofan6/Moect/blob/7498e9f21ab283edb55a5d6a2e17c7ad696cf168/core/favorites.py#L339-L349)、[第三方声明](https://github.com/mofan6/Moect/blob/7498e9f21ab283edb55a5d6a2e17c7ad696cf168/THIRD_PARTY_NOTICES.md#L3-L10)

合成会话文件覆盖 JSON 与 JSONL 的字节哈希、消息和资源字段、转发层级及日期筛选声明，另验证拒绝收藏结构。结论限于离线文件整理。

交给证据技能 1.3.0 时，从 Waylon 的 `manifest.json` 对照 SHA-256 核对同批 Moect 原会话 JSON 或 JSONL，保留原文件名及旁边同批的 `<源文件名去掉扩展名>_assets/`，以便 `neutral-moect` 找到可选 `resource-report.jsonl`。`originals/` 中的改名副本和 `messages.jsonl` 用于 Waylon 复核。资料留在获授权环境。 [wechat-evidence-expert 的 Moect 导入说明](https://github.com/xiezhicong3288-wq/wechat-evidence-expert/blob/main/skills/chat-evidence/references/moect_export.md)
