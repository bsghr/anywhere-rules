# Anywhere Rules

将 BlackMatrix7 的 Shadowrocket/Surge 规则集转换为 Anywhere `.arrs`。

## 设计原则

本项目只做格式转换，不主动重新整理规则：

- 保持源规则顺序；
- 不主动去重；
- 保留支持的规则类型；
- 对 Anywhere 不支持的规则类型进行明确统计；
- 生成的 `.arrs` 使用 `routing` 指定默认策略；
- 规则源直接指向 BlackMatrix7，上游更新后由 GitHub Actions 自动同步。

## 增加规则

编辑 `rules.yml`，例如：

```yaml
rules:
  - name: Apple
    source: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Apple/Apple.list
    output: rules/Apple.arrs
    routing: 0
    description: Apple 规则

  - name: AdvertisingLite
    source: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/AdvertisingLite/AdvertisingLite.list
    output: rules/AdvertisingLite.arrs
    routing: 2
    description: AdvertisingLite 广告拦截规则
```

## 当前规则类型映射

| Shadowrocket | Anywhere |
|---|---:|
| DOMAIN | 1 |
| DOMAIN-SUFFIX | 2 |
| DOMAIN-KEYWORD | 3 |
| IP-CIDR | 4 |
| IP-CIDR6 | 5 |

Anywhere 当前支持域名后缀、域名关键词、IPv4 CIDR 和 IPv6 CIDR；不支持的上游规则类型会被跳过并记录在生成文件头部。

## 使用

Anywhere 直接使用对应 Raw 地址：

```text
https://raw.githubusercontent.com/你的用户名/你的仓库/main/rules/AdvertisingLite.arrs
```

## 自动同步

GitHub Actions 每天自动执行一次，也可以在 Actions 页面手动执行 `Sync BlackMatrix7 Rules`。

## 注意

如果某个 BlackMatrix7 规则集包含 `URL-REGEX`、`USER-AGENT`、`PROCESS-NAME`、`IP-ASN` 等 Anywhere 当前无法表达的规则类型，转换结果会在文件头部通过 `SKIPPED` 和 `SKIPPED-TYPES` 标记。
