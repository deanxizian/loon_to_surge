# Loon 转 Surge 当前转换规则

本文档总结当前项目脚本 `scripts/convert_kelee_to_surge.py` 实际执行的转换规则。规则以脚本实现为准，目标是把 `Loon/*.lpx` 生成可直接导入 Surge 的 `Surge/*.sgmodule`，同时保留无法安全自动映射的项目到 `Surge/convert-report.json`。

参考方向：

- Loon Rewrite V2 官方文档：作为新版 Rewrite 的语法、类型、Action 顺序和执行阶段依据。
- QingRex/LoonKissSurge：主要对照其 Kelee 成品模块的 Surge 输出形态，包括 section 组织、`Map Local`、`http-response-jq`、`extended-matching`、`pre-matching` 等规则标记。
- Script-Hub-Org/Script-Hub：主要参考 `enable={...}` 转 Surge 行前缀开关、参数引号与顶层分隔处理，以及规则标记处理的边界。
- Loon Script 与 Script API 官方文档：用于确认 `generic` 可接收被操作节点的 `$environment.params.node/nodeInfo`。
- Surge 官方文档：作为最终语法边界，覆盖模块结构、`#!arguments`、`#!system`、`#!requirement`、`[Rule]`、`[Script]`、`[Map Local]`、`[MITM]` 和 `pre-matching` 的适用范围；Surge generic/Panel 只使用自身的普通脚本上下文及 `$input/$trigger`，不假设存在 Loon 的被选节点上下文。

当前规则不是对任一项目逐行照搬。参考项目与 Surge Manual 冲突时，以当前 Surge Manual 为准。

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
[Panel]
[Script]
[MITM]
```

生成时会先写入临时目录，转换完成后再替换 `Surge` 目录和报告文件。若生成内容没有变化，`convert-report.json` 里的 `generated_at` 会尽量保持不变。报告中的 `total`、`converted`、`excluded` 分别表示 Loon 输入数、Surge 输出数和主动排除数；Surge 清单与排除报告必须完整覆盖全部 Loon 输入。

输入只接受非空的 `[Argument]`、`[General]`、`[Rule]`、`[Rewrite]`、`[Script]` 和 `[MITM]`。出现其他非空 section，或仅大小写不同的重复 section 时，会记录 `unsupported-section` 并终止发布，避免静默丢掉上游新语法。

## 元数据

Loon 文件里的 `#!` 元数据按以下规则输出：

- 保留：`name`、`desc`、`author`、`icon`
- 固定添加：`#!category=iKeLee`
- 继续保留：`openUrl`、`open`、`tag`、`system_version`、`loon_version`、`homepage`、`date`
- `system` 只输出 Surge 官方支持的 `ios` 或 `mac`：Loon 的 `iOS/iPadOS` 映射为 `ios`，`macOS` 映射为 `mac`；同时覆盖 iOS 和 macOS 时省略限制，`watchOS` 没有 Surge 对应目标。
- 使用模块参数、域名 `extended-matching`、普通 `[Body Rewrite]` 或 `[Map Local]` 的模块添加 `#!requirement=CORE_VERSION>=20`，这是官方已列出的基础兼容门槛。
- 含 `http-request-jq`、`http-response-jq`、`pre-matching`、URL-REGEX `extended-matching`，或使用引号保护含逗号参数默认值的模块添加保守门槛 `#!requirement=CORE_VERSION>=6008000`。Surge Manual/Release Notes 只给出部分新特性的客户端最低版本（JQ 为 iOS 5.14 / Mac 5.9，引号值为 iOS 5.21 / Mac 6.8）；`6008000` 是官方版本表中已确认共同支持这些语法的 Core，会排除部分可能兼容的旧客户端，但不会向不支持这些特性的版本宣称可用。

模块文件名使用模块 `name`，并清理 Windows 不合法文件名字符。重名时自动追加 `-2`、`-3`。

## Argument

Loon `[Argument]` 会转换为 Surge `#!arguments=`。

规则：

- 每行取 `=` 左侧作为参数名。
- 每行逗号分隔后的第二项作为默认值。
- 按 Surge 当前表格语法输出 `参数名:默认值,参数名2:默认值2`，不做 URL 编码。
- 参数名只保留 ASCII 字母、数字和下划线；其他字符转换为 `_`，数字开头时加 `ARG_`。归一化后重名会阻止发布。
- 脚本参数、cron 或 Rewrite 里的 Loon 占位符 `{Name}` / `${Name}` 会转换成 Surge 模块占位符 `{{{Name}}}`。
- 默认值含逗号时使用双引号保护，并按 Surge 引号值语法转义反斜杠和双引号；对应模块要求 `CORE_VERSION>=6008000`。实际换行仍会记录 `argument-default` 并终止发布。
- 未被任何生成行引用的 Loon 参数会删除，并记录 `argument-unused-dropped`。

示例：

```ini
[Argument]
Cron=select, "0 1 * * *", "0 2 * * *", tag=Cron
```

转换为：

```ini
#!arguments=Cron:0 1 * * *
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
- 只接受已核对 Loon 与 Surge 语义的类型：`DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`、`IP-CIDR6`、`GEOIP`、`IPASN`/`IP-ASN`、`AND`、`OR`、`NOT`、`DEST-PORT`、`PROTOCOL`、`SRC-PORT`、`URL-REGEX`、`USER-AGENT`。
- Loon 的 `IPASN` 会规范为 Surge 的 `IP-ASN`。规则 option 也按类型限制为 Surge 已确认支持的 `extended-matching`、`no-resolve`、`pre-matching` 组合，并递归检查逻辑规则子 matcher；未知类型或 option 会记录 `unsupported-rule` 并终止发布，不能原样透传。

### 裸域名

裸域名会按广告拦截规则处理，并避免重复写入：

```ini
example.com
```

转换为：

```ini
DOMAIN,example.com,REJECT,extended-matching,pre-matching
```

### 模块策略限制

Surge Manual 明确规定模块 `[Rule]` 只允许 `DIRECT`、`REJECT`、`REJECT-TINYGIF`。因此，只要一个 Loon 模块含有 `PROXY`、`REJECT-DROP` 或其他策略，该模块会整项排除并记录一次 `module-excluded`，不会删除单条规则后发布语义残缺的模块。

即使用户主配置中存在名为 `PROXY` 的策略组，官方模块语法仍不保证可以引用它。是否放宽此限制只能依据当前 Surge 真机测试结果，不能根据普通配置文件的 `[Rule]` 能力推断。

### extended-matching

以下规则类型会补充 `extended-matching`：

- `DOMAIN`
- `DOMAIN-SUFFIX`
- `DOMAIN-KEYWORD`
- `URL-REGEX`
- 逻辑规则里的域名类子规则

对于 `DIRECT` 等非拒绝策略规则，只加 `extended-matching`，不加 `pre-matching`。

### pre-matching

生成模块中的 `pre-matching` 只用于允许发布的拒绝策略：`REJECT` 与 `REJECT-TINYGIF`。其他 `REJECT-*` 策略会先触发整模块排除，不会进入这一转换步骤。

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

### Rewrite V2

Loon 3.5.1 (978) 起使用以下新版格式：

```ini
request if ${url} ~= /^https:\/\/example\.com/ then request.header.set("X-Test", "true")
response if ${url} ~= /^https:\/\/example\.com/ then response.json.delete("data.ads")
```

转换器会识别字符串、原始字符串、正则、变量、数组和嵌套括号的边界，不按空格、逗号或 `|` 直接拆分整行。

当前可安全转换的条件：

- 单个 `${url} ~= /regex/`，可使用 `as name` 捕获并在 URL 替换或重定向中引用 `${name.n}`。
- 单个 `${url} == "constant"`，转换为完整 URL 正则。
- URL、Header 和 Body 正则暂不接受 `i`、`m`、`s` flags，避免在没有确认 Surge 等价语义时改变匹配范围；包含这类 Rewrite V2 正则的模块会整项排除并记录 `module-excluded`，不会生成删掉相关行的残缺模块。

当前可安全转换的 Action：

- `url.replace`、`redirect(302|307, ...)` 转为 `[URL Rewrite]`。
- `reject`、`reject_img`、`reject_dict`、`reject_array` 转为 `[Map Local]`，保留状态码、Body 和 Content-Type；`reject_video` 暂不转换。
- Loon V2 的 `reject*` 状态码范围是 `100–599`，Surge Map Local 是 `200–999`，因此只有两端交集 `200–599` 能转换；Loon 合法但 Surge 不接受的 `100–199` 会终止发布。
- `request.header.*`、`response.header.*` 的 `add`、`set`、`del`、`replace` 转为 `[Header Rewrite]`。`set` 使用 `header-del` 后接 `header-add`，避免重复 Header。
- `request.body.replace`、`response.body.replace` 转为 `[Body Rewrite]` 正则替换。
- `request.json.*`、`response.json.*` 的 `add`、`delete`、`replace`、`jq` 转为 Surge JQ Body Rewrite。
- HTTP(S) `json.jq_file` 会抓取并内联；相对资源文件因不包含在独立 `.lpx` 下载结果中而拒绝转换。
- `response.body.mock` 转为 base64 `[Map Local]`；HTTP(S) `response.body.mock_file` 转为 `data-type=file`。
- Header、Body 正则和 JSON 修改的批量数组参数会按原顺序展开。

多个 Action 只有在都能落入同一个 Surge section、且仍能保持从左到右执行语义时才会展开。方法、请求或响应 Header、响应状态码、逻辑组合条件，以及请求 Body Mock、响应 Mock 与 Header 的混合 Action 等，当前都不会被弱化为仅 URL 匹配。

带正则 flags 的 V2 模块会按上述规则整项排除，因此不会阻塞其他模块更新。其他无法安全转换的 V2 行仍会产生 `unsupported-rewrite`；该类型属于致命转换错误，全量任务会在替换 `Surge/` 前失败，上一版已验证产物保持不变。

### URL Rewrite

```ini
pattern reject
```

转换为：

```ini
pattern _ reject
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

转换为空 Body 响应：

```ini
pattern data-type=text data="" status-code=200
```

`mock-response-body` 会转换为 Surge `Map Local` 参数：

- `data-path=` 转为 `data-type=file data=...`
- `data-type=json` 转为 `data-type=text`，并补 `Content-Type:application/json`
- `mock-data-is-base64=true` 转为 `data-type=base64`
- 内联 `data="..."` 如果包含会影响 Surge 解析的引号或换行，会转为 base64，并补合适的 `Content-Type`
- 未指定 `status-code` 时默认补 `status-code=200`
- `status-code` 只接受 Surge Manual 规定的 `200` 至 `999`；超出范围会终止发布

### Body Rewrite

支持以下 JSON 和正则改写：

- `response-body-json-jq`
- `response-body-json-del`
- `response-body-json-replace`
- `response-body-replace-regex`
- `request-body-replace-regex`

其中：

- `response-body-json-jq` 转为 `http-response-jq`。
- `jq-path=<url>` 会尝试抓取远端 jq 内容并内联。抓取失败时报告 `jq-path-inline-failed`，并阻止本次生成结果替换上一版产物。
- `response-body-json-del` 转为 jq `delpaths(...)`。
- `response-body-json-replace` 转为带 `try (getpath(...) | has(...)) catch false` 检查的 `setpath`，避免父路径不存在时 jq 报错，也避免目标路径不存在时误建结构。

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
- `script-update-interval`
- `debug`
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
Job = type=cron, cronexp="{{{Cron}}}", script-path=https://example.com/job.js
```

保留的属性：

- `script-path`
- `timeout`
- `engine`
- `wake-system`
- `script-update-interval`
- `debug`
- `argument`

### generic

Loon generic 与 Surge generic 名称相同，但运行上下文不完全等价。Loon 可以在节点页面手动触发 generic，并通过 `$environment.params.node/nodeInfo` 把被操作节点传给脚本；Surge 官方 generic/Panel 文档没有对应的被选节点参数。因此，本项目不会把任意 Loon generic 直接改名后发布。

只有经过人工核实、脚本本身包含可用 Surge 分支的精确 `script-path` 才会转为：

```ini
Name = type=generic, ...
```

保留的属性：

- `script-path`
- `timeout`
- `engine`
- `script-update-interval`
- `debug`
- `argument`

Loon 的 `img-url` 只用于其 generic 脚本界面，Surge `[Script]` 没有该参数，转换时会移除。

当前核实并允许转换的脚本：

- `https://kelee.one/Resource/JavaScript/NodeLinkCheck/NodeLinkCheck.js`
- `https://raw.githubusercontent.com/VirgilClyne/Cloudflare/main/js/1.1.1.1.panel.js`

这两个脚本不是简单改名：

- `NodeLinkCheck.js` 自带 Surge 分支并原生读取 `$argument.policy`。转换后增加模块参数 `Policy`（默认 `PROXY`），脚本参数为 `policy={{{Policy}}}`，避免脚本在没有参数时退回配置中的第一个策略组；同时移除只描述 Loon 长按节点流程的 `openUrl`，并注明依赖 Sub-Store 节点数据。
- `1.1.1.1.panel.js` 自带 Surge Panel 返回字段。转换后增加与 Script 同名并关联的 `[Panel]`，查询当前 Surge 路由，同时替换掉 Loon 的“长按节点”说明。

两项适配均记录 `generic-script-adapted`，便于复核实际行为。

含有其他 generic `script-path` 的 Loon 模块会整项排除，不生成 `.sgmodule`，也不写入 Surge 索引，并记录 `module-excluded`。这样避免发布可导入但运行时因缺少 Loon 上下文而报错或检测错误节点的模块。新脚本必须先核对其 Surge 分支和实际调用语义，再加入精确白名单。

当前只转换 Loon 旧版 `[Script]` 行。新版 `request/response if ... then script(...)` 同时引入条件表达式、正则 flags 和新的属性结构；在没有逐项确认 Surge 等价语义前，包含 Script V2 的模块会整项排除并记录 `module-excluded`，不会阻断其他模块更新，也不会生成只保留部分功能的 Surge 模块。

所有旧版 Script 类型都要求非空 `script-path`。未知属性、冲突的重复属性或无效布尔值会记录为 `unsupported-script` 并阻止发布；相同值的重复属性会安全去重并记录 `script-property-corrected`。

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

`Surge/convert-report.json` 用于记录成功转换后仍需人工知情的项目。转换期间也使用相同类型收集错误，但致命错误会直接终止任务，不覆盖上一版报告和模块。当前常见类型：

- `argument-unused-dropped`：Loon 声明了参数，但任何生成行都未引用，参数已从 Surge 输出删除。
- `generic-script-adapted`：已核实的 generic 使用其原生 Surge 接口补充了 Policy 参数或 Panel 配置。
- `module-excluded`：模块含有 Surge 模块不允许的 Rule 策略、未经核实的 Loon generic 脚本、没有已验证 Surge 等价语义的 Rewrite V2 正则 flags、尚未支持的 Script V2，或其他不可安全发布的模块级问题，已从 Surge 输出和索引中排除。
- `script-enable-toggle-emitted`：`enable={Arg}` 已转为 Surge 行前缀开关。
- `script-enable-shared-commented`：`enable` 参数同时是脚本入参，脚本行按默认值静态注释，参数默认值保留。
- `script-enable-direct-commented`：`enable=false` 已转为注释脚本行。
- `script-enable-direct-kept`：`enable=true` 已直接保留脚本行。
- `script-property-corrected`：相同值的重复 Script 属性已安全去重。
- `rewrite-empty-skipped`：上游存在空 JQ，Surge 不接受空程序，因此跳过该无有效操作的行。
- `rewrite-action-corrected`：上游把完整 `del(...)` JQ 写在 JSON delete Action 后，按完整 JQ 原样转换，避免按空格拆坏。
- `jq-expression-corrected`：上游 JQ 缺少变量绑定所需的分组，补齐括号后再输出。
- `general-pass-through`：`[General]` 行原样透传。
- `jq-path-inline-failed`：远端 jq 抓取失败，保留原表达式。
- `unsupported-rewrite`：Rewrite 动作不支持或无法解析。
- `unsupported-header-rewrite`：Header rewrite 无法解析。
- `unsupported-script`：Script 行不支持或无法解析。
- `unsupported-rule`：Loon Rule 类型/option 未知、字段不完整或逻辑 matcher 无法安全转换。
- `unsupported-section`：Loon 出现未知的非空 section，或仅大小写不同的重复 section。
- `argument-parse`：Argument 行无法解析。
- `argument-default`：Argument 行找不到默认值，或默认值含无法写入单行 Surge 参数表的实际换行。
- `argument-name-collision`：参数名归一化后重名。
- `mitm-unsupported`：MITM 行不支持。
- `unsupported-system`：Loon 平台限制无法映射为 Surge 的 `ios/mac`。

`argument-unused-dropped`、`generic-script-adapted`、`module-excluded`、`script-enable-*`、`script-property-corrected`、`rewrite-empty-skipped`、`rewrite-action-corrected` 和 `jq-expression-corrected` 是成功生成后的知情报告；其中 `module-excluded` 表示对应模块没有发布到 Surge。`general-pass-through`、`jq-path-inline-failed`、`unsupported-*`、`argument-parse`、`argument-default`、`argument-name-collision`、`mitm-unsupported` 属于致命转换错误；出现时 GitHub Action 失败并保留上一版 Surge 产物。

因此，成功生成的 `convert-report.json` 中存在 warning 不等于模块不可用。当前上游的空 JQ 和错标 JQ 会被明确记录，不会生成空规则或拆坏的规则。

## 当前安全边界

当前转换明确不做以下事情：

- 不把 `PROXY`、`REJECT-DROP` 自动改成其他策略；含这类模块规则的模块会整项排除。
- 不假设用户 Surge 配置里有某个自定义策略组。
- 不给非拒绝类规则添加 `pre-matching`。
- 不把共享脚本参数强行改成 `#` 开关。
- 不把未经核实的 Loon generic 当作 Surge generic 发布。
- 不把尚未核实条件、正则和属性映射的 Loon Script V2 强行改写为 Surge Script。
- 不原样透传未知 Rule 类型，也不静默忽略未知的非空 Loon section。
- 不静默吞掉未知语法，无法安全转换时终止整次生成并保留上一版产物。

## 当前验证口径

每次调整转换规则后，应至少执行：

```powershell
python scripts\convert_kelee_to_surge.py --input-dir Loon --output-dir Surge --report-path Surge\convert-report.json
python scripts\validate_surge_modules.py --loon-dir Loon --surge-dir Surge --report-path Surge\convert-report.json
python -m unittest discover -s tests
git diff --check
```

还应扫描生成的 `Surge/*.sgmodule`，确认：

- 没有 Loon `enable=` 或 `enabled?=` 残留。
- 没有 Loon Rewrite V2 的 `request if ... then` 或 `response if ... then` 残留。
- 所有 `http-request-jq`、`http-response-jq` 表达式均通过真实 `jq` 编译。
- 没有旧式 `%Arg%` 或裸 `{Arg}` 占位符残留，模块参数应使用 `{{{Arg}}}`。
- `#!arguments` 使用 `name:default,name2:default` 表格语法，参数名唯一，且每个参数都被生成内容引用。
- URL Rewrite 的拒绝行使用 `_ reject`。
- 模块 `[Rule]` 只含已核对的规则类型，并且策略只含 `DIRECT`、`REJECT`、`REJECT-TINYGIF`。
- `#!system` 只可能是 `ios` 或 `mac`。
- 模块参数、域名 `extended-matching`、普通 `[Body Rewrite]` / `[Map Local]` 使用 `CORE_VERSION>=20`；JQ、`pre-matching` 和 URL-REGEX `extended-matching` 使用保守门槛 `CORE_VERSION>=6008000`。
- 所有 Map Local `status-code` 都在 `200` 至 `999`。
- Surge 清单与 `module-excluded` 报告合起来完整覆盖全部 Loon 模块。
- 每个动态 `[Panel]` 引用的 `script-name` 都存在于同一模块的 `[Script]`。
- 非拒绝策略没有 `pre-matching`。
- 需要 `extended-matching` 的域名类、`URL-REGEX` 规则已经补齐。

## 真机验证

静态校验可以确认语法形状、占位符、section、规则策略和 JQ 编译，但不能证明 Surge 的参数 UI、MITM、第三方脚本及目标 App 的实际行为。以下项目必须在最新版 Surge 真机上验证。

测试前先备份当前配置，安装并信任 Surge MITM CA；只在测试期间启用对应模块，查看 Surge 日志和最近请求，完成后删除临时模块。

### 1. 模块参数与 enable 行前缀

使用 `WPS每日签到.sgmodule`：

1. 导入后打开模块参数，确认 `CaptureCookie` 默认值显示为 `#`，`CRONEXP` 显示为 `0 8 * * *`，且无未使用的 `DAY`。
2. 保持 `CaptureCookie=#`，重新应用模块；捕获 Cookie 的 http-request 脚本应保持禁用。
3. 将 `CaptureCookie` 清空并重新应用；该脚本应启用，cron 表达式仍应完整保留空格。
4. 若 Surge 不允许保存空参数、保留了 `{{{CaptureCookie}}}`，或脚本状态与预期相反，则 `enable={Arg}` 行前缀方案不能视为可用。

### 2. Rewrite V2 转换

使用 `Telegram重定向.sgmodule`：

1. 在参数中分别选择 `tg` 和 `sg`。
2. 打开带路径捕获的 `https://t.me/<name>` 链接。
3. 确认重定向协议随参数变化，`<name>` 被完整带入目标 URL，Surge 日志没有 URL Rewrite 解析错误。

### 3. HTTP Rewrite、Map Local 与 JQ

至少分别测试：`小蚕霸王餐去广告.sgmodule` 的 Header Rewrite、`36氪去广告.sgmodule` 的 Body Rewrite/Map Local，以及一个含 `http-response-jq` 的常用模块。

1. 启用 MITM 和模块，清除目标 App 缓存后重新发起请求。
2. 在最近请求中确认命中了对应 URL，响应被修改，日志中没有正则、JQ、Body Rewrite 或 Map Local 错误。
3. JQ Body Rewrite 官方最低版本是 Surge iOS 5.14 / Mac 5.9。项目为 JQ 模块使用已确认兼容的保守门槛 `CORE_VERSION>=6008000`（iOS 5.21 / Mac 6.8 对应的共同 Core）；仍应使用最新版 Surge 实测。

### 4. generic 与 Panel

- `WARP节点查询.sgmodule`：Panel 能显示并刷新当前 Surge 路由信息，日志无脚本异常。
- `代理链路检测.sgmodule`：准备有效的 Sub-Store 节点数据，分别选择两个真实策略，确认 `$argument.policy` 生效且检测的是所选策略。

### 5. 平台限制

在 iOS 导入 `555电影去广告.sgmodule`，确认 `#!system=ios` 被接受；再在 Surge Mac 尝试同一模块，确认客户端按平台限制拒绝或隐藏。`YouTube去广告.sgmodule` 不带平台限制，应能在两端导入。

### 6. 官方未允许的 Rule 策略

这是决定能否恢复策略型排除模块的关键 A/B 测试。先确保主配置确实存在 `PROXY` 策略组，再手工导入仅含下列内容的临时模块：

```ini
#!name=External Policy Smoke Test

[Rule]
DOMAIN,example.com,PROXY,extended-matching
```

记录三个结果：是否能导入、是否能启用、请求 `example.com` 时是否实际命中该规则。再把策略改成 `REJECT-DROP` 重复测试。只有当前 iOS 与 Mac Surge 都能稳定导入并实际生效，才有依据放宽官方文档规定的 `DIRECT/REJECT/REJECT-TINYGIF` 限制；仅“文件能导入”不算通过。
