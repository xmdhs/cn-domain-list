# cn-domain-list
使用 Cloudflare Radar 的前 100 万域名，使用中国 dns 解析为 ip，判断是否是中国 ip。并去除 Loyalsoldier/v2ray-rules-dat 中 `geosite:geolocation-!cn` 中存在的域名，生成一份额外的中国大陆域名。

```json
{
    "tag": "ext-cn-domain",
    "type": "remote",
    "format": "binary",
    "url": "https://raw.githubusercontent.com/xmdhs/cn-domain-list/rule-set/ext-cn-list.srs"
}
```

海外域名（通常无需使用，约90w+域名，内存占用较大）
```json
{
    "tag": "ext-not-cn-domain",
    "type": "remote",
    "format": "binary",
    "url": "https://raw.githubusercontent.com/xmdhs/cn-domain-list/rule-set/ext-not-cn-list.srs"
}
```

## mihomo
```yaml
rule-providers:
  ext-cn-list:
    type: http
    behavior: domain
    url: "https://raw.githubusercontent.com/xmdhs/cn-domain-list/rule-set/ext-cn-list.yaml"
    path: ./ext-cn-list.yaml
    interval: 86400

  ext-not-cn-list:
    type: http
    behavior: domain
    url: "https://raw.githubusercontent.com/xmdhs/cn-domain-list/rule-set/ext-not-cn-list.yaml"
    path: ./ext-not-cn-domain.yaml
    interval: 86400
```
