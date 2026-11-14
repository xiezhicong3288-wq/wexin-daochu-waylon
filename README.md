# wexin-daochu-waylon

微信聊天本机导出与中立归档，保留原文与来源。

## 安装

交给支持 Skill 安装的助手或宿主安装仓库根目录的 [SKILL.md](SKILL.md) 及配套文件：

```text
https://github.com/xiezhicong3288-wq/wexin-daochu-waylon
```

## 用法

```text
使用 $wexin-daochu-waylon，在已授权本机核对我指定的账号与会话，
先做小范围导出，再按显示名中立整理，列出缺失和失败。
```

```text
python scripts/normalize_export.py --input <Moect导出JSON或JSONL> --account-scope <已确认范围> --out <全新目录>
```

命令与参数见 [执行命令](references/commands.md)。验收判据、条款级追溯矩阵、外部锚定契约与失效条件见 [验收要求](references/acceptance.md)；按矩阵逐项核对回执，不以生成文件或退出码代替。只有导出文件、没有原始数据库时，结论限于整理保真。

## 运行环境

独立 Python 3.11+ 环境；运行组件与聊天材料放在技能目录之外。本机提取仅限已授权的 Windows 电脑与已确认的微信版本。私有仓库访问使用你自己的 GitHub 授权。

## 许可

GPL-3.0，沿用上游 [Moect](https://github.com/mofan6/Moect) v1.2.8；完整原文见 [LICENSE](LICENSE)，来源与改造边界见 [references/source-adaptation.md](references/source-adaptation.md)。
