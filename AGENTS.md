# 开发与维护

本文件供修改仓库的编码助手和维护者使用。具体转换语义及官方文档依据见 [RULES.md](RULES.md)；README 保持面向使用者，提供项目介绍、使用步骤、自动更新说明和简短的本地运行入口，完整的开发与验证流程放在本文件。

## 项目结构

- `Loon/`：抓取到的原始插件、列表和索引。
- `Surge/`：生成的模块、索引与 `convert-report.json`。
- `scripts/update_kelee_modules.py`：抓取、转换和校验的完整入口。
- `scripts/convert_kelee_to_surge.py`、`scripts/validate_surge_modules.py`：转换与独立产物校验。
- `scripts/script_v2_compat.py`、`scripts/source_quality.py`、`scripts/source_repairs.py`：已核验的脚本适配、源内容检查和精确版本补丁。
- `tests/fixtures/`：语义回归样例、源版本及审查依据；`index.html` 为模块网站。

## 修改约定

- 调整转换逻辑时，同步更新 RULES.md 和覆盖实际语义差异的回归测试。详细的类型、正则、执行顺序和最低版本要求统一记录在 RULES.md。
- 保留原始下载内容，通过转换器生成 Surge 产物。无法保证等价的能力应明确排除并记录原因；畸形语法和已确认的源内容错误应阻止发布，不能降级为普通警告。
- 保持候选产物先校验、再替换的流程；校验失败时保留上一版 Surge 产物。JQ 校验必须使用真实 `jq`。
- 已核验的 Object 参数适配依赖精确脚本 URL 和 SHA-256；上游补丁依赖精确源文件、行及结果 hash。未知版本需重新核对语义并更新依据，不能仅替换 hash 来让检查通过。补丁只在内存应用，原始下载文件保持不变。
- README 不记录某次运行的模块数、测试数或补丁明细。当前转换状态查 `Surge/convert-report.json`，审查依据查 `tests/fixtures/`。

## 本地命令

准备 Python 3 和 `jq`，从仓库根目录执行。仅修改文档时，检查链接、格式与 `git diff --check` 即可。

修改转换逻辑后，运行测试，并将候选结果生成到临时目录；转换入口会在写入目标目录前完成独立校验和 JQ 编译：

```sh
python3 -m unittest discover -s tests
python3 scripts/convert_kelee_to_surge.py --input-dir Loon --output-dir .tmp/check/Surge --report-path .tmp/check/Surge/convert-report.json --require-jq
git diff --check
```

校验仓库中已有的发布产物：

```sh
python3 scripts/validate_surge_modules.py --require-jq
```

macOS 上还可执行 CI 使用的 Foundation 正则对照检查：

```sh
swift tests/verify_url_ignore_case.swift
swift tests/verify_body_regex_flags.swift
```

需要抓取最新上游并刷新产物时运行以下命令；它会更新 `Loon/` 和 `Surge/`：

```sh
python3 scripts/update_kelee_modules.py
```

抓取为空、URL 无效或重复、下载不完整、模块数量一次下降超过 20% 时会阻止更新。确认上游确实大规模删除后，才使用 `--allow-large-drop`。

## 远程脚本检查

```sh
python3 scripts/check_remote_scripts.py
```

结果写入 `.tmp/remote-script-audit.json`，包含下载状态、SHA-256、引用位置和待复核 API 的文本线索。该检查仅下载并检查文本，不执行 JavaScript；默认报告问题而不因单个 URL 失败阻断更新。`--strict` 可令下载失败或 API 线索返回非零状态，`--user-agent` 可复查按客户端限制访问的资源。

这项审计与 Object 适配的必需验签不同：后者的下载失败或 hash 变化会阻止发布。静态检查、平台标记及 Surge CLI 配置检查都不能替代真实流量验证，具体步骤见 RULES.md。

## CI 与发布

- PR 工作流检查 Python 测试、仓库产物、JQ、格式和 macOS Foundation 正则；不抓取上游，也不提交生成结果。按既有协作流程，等待 CI 和 GitHub Codex review 完成，处理有效意见后再合并。
- 更新工作流计划每日 UTC 16:00（北京时间次日 00:00）执行，也支持手动运行。它抓取并校验模块、运行测试和远程脚本审计，有变化时提交 `Loon/`、`Surge/`。审计附件名为 `remote-script-audit`，保留 30 天。
- 本次任务包含产物发布时，合并代码后核对更新工作流、机器人提交及转换报告；检查远程脚本审计，不把 Action 成功等同于所有插件都可用。纯文档修改无需刷新模块产物。
