# Loon 转 Surge 当前转换规则

本文档总结当前项目脚本 `scripts/convert_kelee_to_surge.py` 实际执行的转换规则。规则以脚本实现为准，目标是把 `Loon/*.lpx` 生成可直接导入 Surge 的 `Surge/*.sgmodule`，同时保留无法安全自动映射的项目到 `Surge/convert-report.json`。

参考方向：

- QingRex/LoonKissSurge：主要对照其 Kelee 成品模块的 Surge 输出形态，包括 section 组织、`Map Local`、`http-response-jq`、`extended-matching`、`pre-matching` 等规则标记。
- Script-Hub-Org/Script-Hub：主要参考 `enable={...}` 转 Surge 行前缀开关的方式，以及规则标记处理的边界。
- Surge 官方文档：作为最终语法边界，覆盖模块结构、`#!arguments`、`[Rule]`、`[Script]`、`[Map Local]`、`[MITM]` 和 `pre-matching` 的适用范围。

当前规则不是对任一项目逐行照搬。特别是 `PROXY`：Surge 官方公共模块语义更偏向内置策略，但本项目目标配置明确存在 `PROXY` 策略组，因此当前会保留 `PROXY` 规则，并在报告中记录 `external-policy`。

## 输出文件

- 输入：`Loon/*.lpx`
- 输出：`Surge/*.sgmodule`
- 索引：`Surge/modules.index.json`
- 报告：`Surge/convert-report.json`

输出 section 顺序固定为：

```ini
[General]
[Rule]
[URL Rewrite]
[Header Rewrite]
[Body Rewrite]
[Map Local]
[Script]
[MITM]
```

生成时会先写入临时目录，转换完成后再替换 `Surge` 目录和报告文件。若生成内容没有变化，`convert-report.json` 里的 `generated_at` 会尽量保持不变。

## 元数据

Loon 文件里的 `#!` 元数据按以下规则输出：

- 保留：`name`、`desc`、`author`、`icon`
- 固定添加：`#!category=iKeLee`
- 继续保留：`openUrl`、`open`、`tag`、`system`、`system_version`、`loon_version`、`homepage`、`date`

模块文件名使用模块 `name`，并清理 Windows 不合法文件名字符。重名时自动追加 `-2`、`-3`。

## Argument

Loon `[Argument]` 会转换为 Surge `#!arguments=`。

规则：

- 每行取 `=` 左侧作为参数名。
- 每行逗号分隔后的第二项作为默认值。
- 输出格式为 `参数名:默认值`。
- 脚本参数或 cron 里的 Loon 占位符 `{Name}` 会转换成 Surge 模块占位符 `{{{Name}}}`。

示例：

```ini
[Argument]
Cron=select, "0 1 * * *", "0 2 * * *", tag=Cron
```

转换为：

```ini
#!arguments=Cron:"0 1 * * *"
```

## General

当前只特殊处理一类：

```ini
real-ip = example.com
```

转换为：

```ini
always-real-ip = %APPEND% example.com
```

其他 `[General]` 行会原样透传，并在报告中记录 `general-pass-through`，表示没有做专门语义转换。

## Rule

### 基础处理

- 会去掉规则行尾的独立 `//` 注释。
- 逗号两侧空格会标准化。
- 空行和注释行不会进入输出。

### 裸域名

裸域名会按广告拦截规则处理，并避免重复写入：

```ini
example.com
```

转换为：

```ini
DOMAIN,example.com,REJECT,extended-matching,pre-matching
```

### PROXY 策略

`PROXY` 策略规则会保留，并写入报告 `external-policy`。

原因：当前目标 Surge 配置明确存在名为 `PROXY` 的策略或策略组，因此保留这类规则才能保持原模块语义。报告只用于提醒：这些模块依赖目标 Surge 主配置提供 `PROXY`。

示例：

```ini
DOMAIN,example.com,PROXY
```

转换为：

```ini
DOMAIN,example.com,PROXY,extended-matching
```

非拒绝策略不会添加 `pre-matching`。

### extended-matching

以下规则类型会补充 `extended-matching`：

- `DOMAIN`
- `DOMAIN-SUFFIX`
- `DOMAIN-KEYWORD`
- `URL-REGEX`
- 逻辑规则里的域名类子规则

对于代理类或其他非拒绝策略规则，只加 `extended-matching`，不加 `pre-matching`。

### pre-matching

`pre-matching` 只留给拒绝类规则：

- `REJECT`
- `REJECT-DROP`
- `REJECT-NO-DROP`
- 其他以 `REJECT` 开头的策略

对非拒绝策略，如果原 Loon 规则里带了 `pre-matching`，转换时会移除。

IP 类拒绝规则会同时补充：

```ini
no-resolve,pre-matching
```

### 逻辑规则

`AND`、`OR`、`NOT` 会递归转换内部 matcher：

- 内部域名类 matcher 补 `extended-matching`。
- 内部 IP 类 matcher 补 `no-resolve`。
- 顶层逻辑规则只有在策略是拒绝类，且所有子 matcher 都支持 `pre-matching` 时，才补 `pre-matching`。
- 不在逻辑规则本身补 `extended-matching`。

### URL-REGEX 特例

以下 Loon 规则会转成 Surge `Map Local`：

```ini
URL-REGEX,^https://example.com/config,REJECT-DICT
URL-REGEX,^https://example.com/ad.png,REJECT-IMG
```

分别转换为：

```ini
^https://example.com/config data-type=text data="{}" status-code=200 header="Content-Type:application/json"
^https://example.com/ad.png data-type=tiny-gif status-code=200
```

## Rewrite

Loon `[Rewrite]` 会按动作分流到 Surge 的 `[URL Rewrite]`、`[Header Rewrite]`、`[Body Rewrite]` 或 `[Map Local]`。

### URL Rewrite

```ini
pattern reject
```

转换为：

```ini
pattern - reject
```

```ini
pattern header replacement
```

转换为：

```ini
pattern replacement header
```

```ini
pattern 302 replacement
```

转换为：

```ini
pattern replacement 302
```

### Map Local

```ini
pattern reject-dict
```

转换为空 JSON：

```ini
pattern data-type=text data="{}" status-code=200 header="Content-Type:application/json"
```

```ini
pattern reject-img
```

转换为 tiny gif：

```ini
pattern data-type=tiny-gif status-code=200
```

```ini
pattern reject-200
```

转换为空白响应：

```ini
pattern data-type=text data=" " status-code=200
```

`mock-response-body` 会转换为 Surge `Map Local` 参数：

- `data-path=` 转为 `data-type=file data=...`
- `data-type=json` 转为 `data-type=text`，并补 `Content-Type:application/json`
- `mock-data-is-base64=true` 转为 `data-type=base64`
- 内联 `data="..."` 如果包含会影响 Surge 解析的引号或换行，会转为 base64，并补合适的 `Content-Type`
- 未指定 `status-code` 时默认补 `status-code=200`

### Body Rewrite

支持以下 JSON 和正则改写：

- `response-body-json-jq`
- `response-body-json-del`
- `response-body-json-replace`
- `response-body-replace-regex`
- `request-body-replace-regex`

其中：

- `response-body-json-jq` 转为 `http-response-jq`。
- `jq-path=<url>` 会尝试抓取远端 jq 内容并内联。抓取失败时保留原值，并报告 `jq-path-inline-failed`。
- `response-body-json-del` 转为 jq `delpaths(...)`。
- `response-body-json-replace` 转为带 `getpath` 检查的 `setpath`，避免目标路径不存在时误建结构。

### Header Rewrite

```ini
pattern response-header-add ...
```

转换为：

```ini
http-response pattern header-add ...
```

```ini
pattern header-replace-regex HeaderName Regex Value
```

转换为：

```ini
http-request pattern header-replace-regex 'HeaderName' 'Regex' 'Value'
```

无法解析或不支持的 rewrite 会进入报告：

- `unsupported-rewrite`
- `unsupported-header-rewrite`

## Script

### http-request / http-response

Loon 脚本：

```ini
http-request pattern script-path=https://example.com/a.js, tag=Name
```

转换为 Surge：

```ini
Name = type=http-request, pattern=pattern, script-path=https://example.com/a.js
```

保留的属性：

- `script-path`
- `requires-body`
- `binary-body-mode`
- `timeout`
- `engine`
- `max-size`
- `ability`
- `argument`

其中 `requires-body=false` 和 `binary-body-mode=false` 会省略。

`argument` 会统一加双引号，内部 `{Name}` 会转换为 `{{{Name}}}`。

### cron

Loon cron：

```ini
cron {Cron} script-path=https://example.com/job.js, tag=Job
```

转换为：

```ini
Job = type=cron, cronexp={{{Cron}}}, script-path=https://example.com/job.js
```

保留的属性：

- `script-path`
- `timeout`
- `engine`
- `wake-system`
- `argument`

### generic

Loon generic script 转为：

```ini
Name = type=generic, ...
```

保留的属性：

- `script-path`
- `timeout`
- `engine`
- `img-url`

## Script enable 开关

`enable` 是 Loon 脚本行的开关。Surge 模块没有同名字段，因此当前采用 Script-Hub 风格的行前缀方案。

### enable={Arg}

如果 `Arg` 只作为脚本开关使用：

```ini
[Argument]
Capture=select, false, true, tag=Capture

[Script]
http-request ^https://example.com script-path=https://example.com/a.js, tag=Capture, enable={Capture}
```

转换为：

```ini
#!arguments=Capture:#

[Script]
{{{Capture}}}Capture = type=http-request, pattern=^https://example.com, script-path=https://example.com/a.js
```

默认值规则：

- `false`、`0`、`off`、`no`、空值、`#` 转为 `#`，表示默认注释掉脚本行。
- 其他默认值转为空字符串，表示默认启用脚本行。

### enable=true / enable=false

静态开关会直接折叠：

- `enable=false`：脚本行前加 `#`
- `enable=true`：脚本行正常输出

### enable 参数同时也是脚本入参

如果同一个参数既用于 `enable={Arg}`，又用于 `argument={Arg}` 或 cron 表达式，为避免把普通入参默认值改成 `#`，当前不会使用 `{{{Arg}}}` 行前缀开关。

处理方式：

- 保留 `#!arguments=Arg:false` 这类原始布尔默认值。
- 根据默认值静态注释或保留对应脚本行。
- 写入报告 `script-enable-shared-commented` 或 `script-enable-shared-kept`。

这个规则是为了保证脚本运行时拿到的参数类型不被开关前缀破坏。

## MITM

只支持：

```ini
hostname = example.com, *.example.org
```

转换为：

```ini
hostname = %APPEND% example.com, *.example.org
```

其他 MITM 行不会猜测转换，会写入报告 `mitm-unsupported`。

## 报告类型

`Surge/convert-report.json` 用于记录需要人工知情或暂不支持的项目。当前常见类型：

- `external-policy`：规则使用 `PROXY`，目标 Surge 主配置需要有同名策略或策略组。
- `script-enable-toggle-emitted`：`enable={Arg}` 已转为 Surge 行前缀开关。
- `script-enable-shared-commented`：`enable` 参数同时是脚本入参，脚本行按默认值静态注释，参数默认值保留。
- `script-enable-direct-commented`：`enable=false` 已转为注释脚本行。
- `script-enable-direct-kept`：`enable=true` 已直接保留脚本行。
- `general-pass-through`：`[General]` 行原样透传。
- `jq-path-inline-failed`：远端 jq 抓取失败，保留原表达式。
- `unsupported-rewrite`：Rewrite 动作不支持或无法解析。
- `unsupported-header-rewrite`：Header rewrite 无法解析。
- `unsupported-script`：Script 行不支持或无法解析。
- `argument-parse`：Argument 行无法解析。
- `argument-default`：Argument 行找不到默认值。
- `mitm-unsupported`：MITM 行不支持。

报告不是一定表示模块不可用。它表示脚本没有在不确定语义下硬猜，需要使用者知情。

## 当前安全边界

当前转换明确不做以下事情：

- 不把 `PROXY` 自动改成其他策略；当前会原样保留为 `PROXY`。
- 不假设用户 Surge 配置里有某个自定义策略组。
- 不给非拒绝类规则添加 `pre-matching`。
- 不把共享脚本参数强行改成 `#` 开关。
- 不静默吞掉未知语法，无法安全转换时写入报告。

## 当前验证口径

每次调整转换规则后，应至少执行：

```powershell
python scripts\convert_kelee_to_surge.py --input-dir Loon --output-dir Surge --report-path Surge\convert-report.json
python -m unittest discover -s tests
git diff --check
```

还应扫描生成的 `Surge/*.sgmodule`，确认：

- 没有 Loon `enable=` 或 `enabled?=` 残留。
- 没有裸 `{Arg}` 占位符残留，应该是 `{{{Arg}}}`。
- `PROXY` 规则没有被错误添加 `pre-matching`。
- 非拒绝策略没有 `pre-matching`。
- 需要 `extended-matching` 的域名类、`URL-REGEX` 规则已经补齐。
