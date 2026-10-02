# loon_to_surge

同步 [可莉插件中心](https://hub.kelee.one/) 的 Loon 插件，保留原始文件，并将支持的功能转换为 Surge 模块。网站提供搜索和一键导入，转换报告记录未支持的插件及原因。

## 使用

打开 **[模块网站](https://loon-to-surge.vercel.app)**：

1. 搜索需要的插件。
2. 选择 Loon 或 Surge，点击对应的导入按钮。
3. 在客户端启用插件，并按模块说明填写参数。

也可以直接浏览仓库中的 [Loon 插件](Loon/) 和 [Surge 模块](Surge/)。请使用满足插件或模块最低版本要求的客户端。

## 自动更新

[GitHub Actions](https://github.com/deanxizian/loon_to_surge/actions/workflows/update-kelee-modules.yml) 计划每天北京时间 00:00 抓取上游、转换模块并自动提交更新。实际运行状态以 Actions 页面为准。

下载或转换校验失败时，保留上一版 Surge 产物。当前发布的转换结果、警告和排除原因见 [转换报告](Surge/convert-report.json)。

## 兼容说明

- 支持已实现的 Loon 旧语法及 Rewrite V2、Script V2 转换；部分功能无法在 Surge 中等价表达，对应插件会被排除。详细范围见 [转换规则](RULES.md)。
- Surge 参数框不会限制可选值，请按模块说明填写。参数及脚本开关的填写方式见 [参数说明](RULES.md#argument)。
- 通过静态校验不代表所有脚本都经过真机测试，实际效果还会受到客户端版本、个人配置及远程脚本的影响。
- 远程脚本的下载状态可在更新任务的 `remote-script-audit` 附件中查看；Action 成功不代表所有远程脚本都可用。

## 项目结构

| 目录 | 内容 |
| --- | --- |
| [Loon/](Loon/) | 上游原始插件与索引 |
| [Surge/](Surge/) | 生成的模块、索引和转换报告 |
| [scripts/](scripts/) | 抓取、转换与校验脚本 |
| [tests/](tests/) | 回归测试与已核验的源文件样例 |

## 本地运行

准备 Python 3 和 `jq`，在仓库根目录执行：

```sh
python3 scripts/update_kelee_modules.py
```

这会抓取最新上游并更新 `Loon/`、`Surge/`。单独转换、校验、测试和远程脚本检查的命令见 [开发与维护](AGENTS.md)。

## 文档与来源

- [转换规则](RULES.md)：支持范围、转换语义与真机验证说明。
- [开发与维护](AGENTS.md)：修改约定、本地命令、校验与发布流程。
- [luestr/ProxyResource](https://github.com/luestr/ProxyResource)：上游插件来源；其他转换参考列在 RULES.md 中。
