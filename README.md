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

成功生成后的 warning 是需要知情的转换事项。Surge 官方规定模块规则只能使用 `DIRECT`、`REJECT`、`REJECT-TINYGIF`，因此含 `PROXY`、`REJECT-DROP` 等策略的模块会整项排除；依赖 Loon 专属运行上下文的未知 `generic` 模块、使用无已验证 Surge 等价语义的 Rewrite V2 正则 flags，或使用尚未核实转换语义的 Script V2 的模块也不会强行转换，均记录为 `module-excluded`。已核实具有 Surge 分支的脚本会使用原生参数或 Panel 配置并记录 `generic-script-adapted`。其他无法安全转换的语法会直接使任务失败，并在覆盖前保留上一版 Surge 产物。

## 自动更新

GitHub Actions 每天 00:00（Asia/Shanghai）运行：

```text
.github/workflows/update-kelee-modules.yml
```

流程会抓取最新 Kelee 模块，重新生成 `Loon/` 和 `Surge/`，如有变化则自动提交。抓取结果为空、条目缺少有效 HTTP(S) URL、URL 重复、下载不完整，或模块总数一次下降超过 20% 时，任务会在替换现有文件前失败；确认上游确实进行了大规模删除后，才可手工使用 `--allow-large-drop` 放行。

## 本地转换

```powershell
python scripts\update_kelee_modules.py
python scripts\validate_surge_modules.py --loon-dir Loon --surge-dir Surge --report-path Surge\convert-report.json
```

运行测试：

```powershell
python -m unittest discover -s tests
```

## 转换参考

- [luestr/ProxyResource](https://github.com/luestr/ProxyResource)：Kelee Loon 模块来源。
- [Loon Rewrite V2](https://nsloon.app/docs/Rewrite/rewrite_v2/)：新版 Rewrite 的语法、类型、Action 和执行顺序依据。
- [QingRex/LoonKissSurge](https://github.com/QingRex/LoonKissSurge)：参考 Kelee 成品模块的 Surge 输出形态，包括 section 组织、`Map Local`、`http-response-jq`、`extended-matching`、`pre-matching` 等。
- [Script-Hub-Org/Script-Hub](https://github.com/Script-Hub-Org/Script-Hub)：参考 `enable={...}` 转 Surge 行前缀开关，以及规则标记处理边界。
- [Surge Manual](https://manual.nssurge.com/)：作为 Surge 模块、配置语法和规则参数的最终依据。

更完整的转换规则和真机验证步骤见 [RULES.md](RULES.md)。
