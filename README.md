# wexin-daochu-waylon

## 中文简介

基于 [Moect](https://github.com/mofan6/Moect) 的微信本机导出与中立整理 Skill，为 Waylon 的授权本机工作流提供可复核的原文、来源和附件索引。

当前适配版本为 **0.2.1**，固定 Moect **v1.2.8**。沿用 **GPL-3.0** 许可，保留上游归属及第三方声明；来源与改造说明见 [references/source-adaptation.md](references/source-adaptation.md)。

## 核心能力

- 在已授权 Windows 本机准备固定版本运行环境，并对确定账号、会话和范围执行提取。
- 将 Moect JSON／JSONL 整理成按显示名组织的会话目录，使用稳定标识区分账号和同名会话。
- 保留原文、发送者依据、原始时间、引用与转发关系，以及附件是否存在、可读取或缺失的状态。
- 为数据库来源提供独立源行参考、记录去向核对和失败位置；未知或未验证的信息明确标记。

真实聊天、账号映射和密钥默认留在授权本机。原生 `ChatPackage/Index/Media/.enc/RMFH` 分包备份不能直接当作已解密数据库导入；具体输入边界见 [SKILL.md](SKILL.md)。

## 安装

将以下仓库地址交给支持 Skill 安装的助手或宿主，安装仓库根目录中的 [SKILL.md](SKILL.md) 及其配套文件：

```text
https://github.com/xiezhicong3288-wq/wexin-daochu-waylon
```

也可以向支持该流程的助手发出：

```text
安装 https://github.com/xiezhicong3288-wq/wexin-daochu-waylon 这个 Skill。
```

安装 Skill 后，按 [执行命令](references/commands.md) 在授权电脑准备独立 Python 3.11+ 运行环境。运行组件与聊天材料放在技能目录之外；私有仓库访问需使用你自己的 GitHub 授权。

## 使用

```text
使用 $wexin-daochu-waylon，在已授权本机核对我指定的账号与会话，
先做小范围导出，再按显示名中立整理。
保留原文、来源、发送者和时间依据、引用关系与附件状态，列出缺失和失败。
```

如果已有 Moect JSON／JSONL，可直接指定文件进行整理；只有导出文件时，结论限于整理保真。后续法律用途由用户另行决定。

版本验证与适用范围见 [验收要求](references/acceptance.md) 和 [0.2.1 验证记录](references/validation-v0.2.1.json)。Windows 合成验证通过不能替代真实聊天试点验收。
