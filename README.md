# loon_to_surge

将 [Kelee](https://hub.kelee.one/) 收录的 Loon 模块抓取到本仓库，并自动转换为 Surge 模块。

## 目录

- `Loon/`：抓取到的原始 Loon 模块。
- `Surge/`：转换后的 Surge 模块、索引和转换报告。
- `scripts/`：抓取、转换和站点数据生成脚本。
- `RULES.md`：当前 Loon 到 Surge 的转换规则说明。

## 使用

打开网站后可以搜索模块，并一键导入 Loon 或 Surge。

Surge 模块文件位于：

```text
Surge/*.sgmodule
```

转换报告位于：

```text
Surge/convert-report.json
```

成功生成后的 warning 是需要知情的转换事项。Surge 官方规定模块规则只能使用 `DIRECT`、`REJECT`、`REJECT-TINYGIF`，因此含 `PROXY`、`REJECT-DROP` 等策略的模块会整项排除。当前支持 Rewrite V2 的 URL `/i`、仅 URL 条件的 HTTP Script V2 和静态 Cron；复杂脚本条件、对象参数、动态属性和新版 generic/network-changed 上下文仍会整模块排除，并记录 `module-excluded`。URL 的 `m/s` 以及 Header/Body 正则 flags 也暂不转换。已核实具有 Surge 分支的旧版 generic 脚本会使用原生参数或 Panel 配置并记录 `generic-script-adapted`。未知属性、无效语法等错误仍会使任务失败，并在覆盖前保留上一版 Surge 产物。

## 自动更新

GitHub Actions 每天 00:00（Asia/Shanghai）运行：

```text
.github/workflows/update-kelee-modules.yml
```

流程会抓取最新 Kelee 模块，重新生成 `Loon/` 和 `Surge/`，如有变化则自动提交。抓取结果为空、条目缺少有效 HTTP(S) URL、URL 重复、下载不完整，或模块总数一次下降超过 20% 时，任务会在替换现有文件前失败；确认上游确实进行了大规模删除后，才可手工使用 `--allow-large-drop` 放行。

转换和测试后会检查输出中引用的远程 JavaScript，记录下载状态、SHA-256、模块引用位置，以及 `$utils.gzip`、`$crypto.aes`、`$dns.query` 的文本线索。每次运行将报告保存为 `remote-script-audit` Actions 附件，保留 30 天。远程脚本检查默认只报告问题；下载失败或出现 API 文本不直接判定整个模块不兼容，也不阻断其他模块更新。

提交到 `main` 的 PR 会运行 Python 测试、已生成模块校验、JQ 编译及 macOS Foundation 正则对照检查。PR 检查不抓取上游模块，也不提交生成结果。

## 本地转换

```powershell
python scripts\update_kelee_modules.py
python scripts\validate_surge_modules.py --loon-dir Loon --surge-dir Surge --report-path Surge\convert-report.json
```

运行测试：

```powershell
python -m unittest discover -s tests
```

单独检查远程脚本（仅下载和检查文本，不执行 JavaScript）：

```powershell
python scripts\check_remote_scripts.py
```

结果保存到 `.tmp/remote-script-audit.json`。可用 `--strict` 在下载失败或发现待复核 API 时返回非零状态；`--user-agent` 可用于复查按客户端限制访问的资源。没有命中 API 文本不代表已经通过 Surge 运行验证。

## 转换参考

- [luestr/ProxyResource](https://github.com/luestr/ProxyResource)：Kelee Loon 模块来源。
- [Loon Rewrite V2](https://nsloon.app/docs/Rewrite/rewrite_v2/)：新版 Rewrite 的语法、类型、Action 和执行顺序依据。
- [Loon Script V2](https://nsloon.app/docs/Script/script_v2/)：五种触发类型、参数类型、属性及默认值依据。
- [Loon Script API](https://nsloon.app/docs/Script/script_api/)：远程脚本运行时能力的复核依据。
- [QingRex/LoonKissSurge](https://github.com/QingRex/LoonKissSurge)：参考 Kelee 成品模块的 Surge 输出形态，包括 section 组织、`Map Local`、`http-response-jq`、`extended-matching`、`pre-matching` 等。
- [Script-Hub-Org/Script-Hub](https://github.com/Script-Hub-Org/Script-Hub)：参考 `enable={...}` 转 Surge 行前缀开关，以及规则标记处理边界。
- [Surge Manual](https://manual.nssurge.com/)：作为 Surge 模块、配置语法和规则参数的最终依据。

更完整的转换规则和真机验证步骤见 [RULES.md](RULES.md)。
