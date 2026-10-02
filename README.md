# loon_to_surge

同步 [可莉插件中心](https://hub.kelee.one/) 的 Loon 插件，并转换为 Surge 模块。

## 使用

访问 **[模块网站](https://loon-to-surge.vercel.app)**，搜索插件后选择导入 Loon 或 Surge。也可以直接浏览仓库中的 [Loon 插件](Loon/) 和 [Surge 模块](Surge/)。

请使用满足模块版本要求的客户端，并按模块说明填写参数。Surge 参数框不会限制可选值；参数和脚本开关的填写方式见 [参数说明](RULES.md#argument)。

## 更新与兼容

[GitHub Actions](https://github.com/deanxizian/loon_to_surge/actions/workflows/update-kelee-modules.yml) 每日自动抓取、转换并更新模块。当前转换结果和排除原因见 [转换报告](Surge/convert-report.json)。

部分 Loon 功能无法等价转换，对应插件会被排除。通过静态校验不代表所有脚本都经过真机测试；远程脚本的可用性仍取决于上游。远程脚本检查结果可在更新任务的 `remote-script-audit` 附件中查看。

## 文档与来源

- [转换规则](RULES.md)：支持范围、转换语义与真机验证说明。
- [开发与维护](AGENTS.md)：项目结构、本地命令、校验与发布流程。
- [luestr/ProxyResource](https://github.com/luestr/ProxyResource)：上游插件来源。
