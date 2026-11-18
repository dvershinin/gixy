---
title: "NGINX CVE"
description: "输入明确的 NGINX 开源版本，检查该版本已知 CVE 与实际配置触发条件；报告受影响的服务器、相关指令、修复版本和官方公告。未提供版本时不推断已安装软件，也不会自动探测二进制文件。该版本同时用于 QUIC BPF 重载风险检查，便于核对升级或供应商补丁。"
---

# NGINX CVE

_Gixy Check ID: `nginx_cves`_

显式传入的 `--nginx-version` 也供 QUIC BPF 检查使用。旧参数
`--nginx-cves-version` 仅在未提供全局版本时作为共享回退值。
Gixy 不会自动检测已安装的二进制文件或软件包版本。


## 概述

`nginx_cves` 检查对应 NGINX 开源版安全公告数据库。请传入 `--nginx-version=1.31.6`，让 gixy 知道将由哪个 NGINX 二进制文件加载该配置；如果不传，该检查将保持静默（gixy 是静态配置分析器，无法获知二进制文件的信息）。

对于纯二进制层面的 CVE，只要提供的版本落在受影响范围内就会报告。与模块或配置模式相关的 CVE，只有在版本和触发条件同时匹配时才会报告，且这些报告会关联到有问题的指令，方便你看到暴露面是在哪里被启用的。

## 用法

```
gixy --nginx-version=1.31.6 /etc/nginx/nginx.conf
```

如果你的二进制文件已打过补丁，对于该发布版本中已修复的任何 CVE，即使配置中仍包含触发模式，该检查也会保持静默。如果没有 `--nginx-version`，该检查将完全静默，因为对于未知的版本，无法做出任何可靠的断言。

## 当前数据库

截至 2026 年 11 月，数据库收录了 [NGINX 开源版官方安全公告页面](https://nginx.org/en/security_advisories.html)上 77 个 CVE 编号中的 73 个，其中包括对已修复的稳定分支版本的更正。有四项被有意排除：仅影响 Windows 的 CVE-2011-4963、CVE-2010-2266 和 CVE-2010-2263，以及 CVE-2009-4487（日志转义问题，严重级别为 none，影响所有版本，无已修复的发布版本）。这些排除项并不意味着已完整覆盖所有与 NGINX 相关的产品。

2026 年 11 月的更新新增十个 CVE。配置前提依据各项
[F5 CNA 记录](https://github.com/CVEProject/cvelistV5/tree/main/cves/2026)，
开源版受影响范围依据官方安全公告页面。

| CVE | 检查的配置前提 |
| --- | --- |
| [CVE-2026-123634](https://www.cve.org/CVERecord?id=CVE-2026-123634) | 同一 HTTP server 中有两个代理上下文，包含相同的带变量主机名表达式及生效的 resolver，且发起上下文启用 SSI 或 mirror。实际子请求路由及主机名相同仍是运行时前提。 |
| [CVE-2026-123007](https://www.cve.org/CVERecord?id=CVE-2026-123007) | 为客户端连接启用 HTTP/2。 |
| [CVE-2026-121810](https://www.cve.org/CVERecord?id=CVE-2026-121810) | QUIC 监听器且生效的 HTTP/3 已启用。 |
| [CVE-2026-123633](https://www.cve.org/CVERecord?id=CVE-2026-123633) | 同一 HTTP server 中启用客户端 HTTP/2 并向后端代理请求。无法静态确定运行时是否缺少 `worker_connections`。 |
| [CVE-2026-118899](https://www.cve.org/CVERecord?id=CVE-2026-118899) | HTTP `listen ... ssl` 且生效的 `ssl_protocols` 包含 `TLSv1.3`。 |
| [CVE-2026-113425](https://www.cve.org/CVERecord?id=CVE-2026-113425) | 已启用的邮件代理服务器。 |
| [CVE-2026-120993](https://www.cve.org/CVERecord?id=CVE-2026-120993) | 同一 stream server 中启用 TLS、动态加载证书，并代理连接且生效 `proxy_protocol v2`。 |
| [CVE-2026-125283](https://www.cve.org/CVERecord?id=CVE-2026-125283) | 生效的 `alias` 和 `try_files` 使用正则 `map` 变量及捕获组。具体捕获组合依赖请求，仍是运行时前提。 |
| [CVE-2026-120967](https://www.cve.org/CVERecord?id=CVE-2026-120967) | 非默认的 TLS stream 虚拟服务器，且生效 `ssl_verify_client on`。 |
| [CVE-2026-123640](https://www.cve.org/CVERecord?id=CVE-2026-123640) | stream 中生效 `ssl_preread on`。 |

其中九项已在开源版 `1.30.7` 和 `1.31.9` 中修复。
CVE-2026-120993 仅影响 `1.31.4`–`1.31.8`，在 `1.31.9` 中修复；
稳定分支不受影响。

HTTP、mail 和 stream 的设置分别限定在各自的协议上下文中。Stream 检查
继承外层 `stream` 块的设置并应用 server 覆盖，不合并同级服务器。
Stream 默认服务器按监听地址和端口确定：显式 `default_server` 优先，否则
使用该监听器的第一个服务器。省略的指令采用 NGINX 文档规定的默认值，
包括从开源版 `1.23.4` 起默认启用 `TLSv1.3`；显式 `off` 和更近层级的覆盖均会生效。
监听器按字面端点分组，纯数字端口规范化为通配地址；不解析 DNS 名称，也不模拟
所有重叠的套接字绑定。

2026 年 9 月的更新包含 HTTP/3 模块中的 CVE-2026-90439，已在开源版 `1.30.5` 和 `1.31.6` 中修复。10 月的版本新增了以下条目：

| CVE | 检查的配置前提 |
| --- | --- |
| [CVE-2026-15176](https://www.cve.org/CVERecord?id=CVE-2026-15176) | 生效的 `alias`、同级或外层的 `rewrite`，以及在适用的 `set`/`return` 表达式或生效的访问日志所用的具名 `log_format` 中直接使用 `$request_filename` 或 `${request_filename}`。 |
| [CVE-2026-93479](https://www.cve.org/CVERecord?id=CVE-2026-93479) | 仅按版本给出建议；无法通过配置完整建模其他不可缓存变量的路径。 |
| [CVE-2026-95101](https://www.cve.org/CVERecord?id=CVE-2026-95101) | 同一 HTTP server 中存在已生效 HTTP/3 的 QUIC 监听器，且 `proxy_pass` 生效的 `proxy_request_buffering` 为 `on`。 |
| [CVE-2026-97629](https://www.cve.org/CVERecord?id=CVE-2026-97629) | TLS HTTP server 生效 `ssl_session_cache shared:...`，启用了会话票据，且没有显式的 `ssl_session_ticket_key` 文件，从而允许自动轮换票据密钥。 |
| [CVE-2026-97205](https://www.cve.org/CVERecord?id=CVE-2026-97205) | 在同一适用的请求上下文中，生效 `ssi on` 并启用了 AIO。 |

10 月的这五个条目均已在 NGINX 开源版 `1.30.6` 和 `1.31.7` 中修复。触发前提参照 [F5 CNA 记录](https://github.com/CVEProject/cvelistV5/tree/main/cves/2026)；历史开源版的版本边界参照 nginx.org，其中 CVE-2026-97629 为 `1.23.2`。检查时会考虑 HTTP/server/location 的继承关系以及更近层级的覆盖，但不会把互不相关的 server 或同级 location 合并在一起。

7 月的条目仍然保持覆盖：CVE-2026-42533（正则 `map` 捕获组与易变输出）、CVE-2026-60005（未命名捕获组配合 `slice` 或后台缓存更新）以及 CVE-2026-56434（SSI 配合未缓冲的代理响应），均已在 `1.30.4` 和 `1.31.3` 中修复。

## 示例

### 由配置触发的 CVE

```
location ~(.*) {
    slice 1m;
    proxy_set_header X-Capture $1;
    proxy_set_header Range $slice_range;
    proxy_pass http://backend;
}
```

```
$ gixy --nginx-version=1.31.2 nginx.conf
==>>> Issue: [MEDIUM] Known nginx CVE affects your installed version.
CVE-2026-60005: Uninitialized memory access in ngx_http_slice_module.
Your installed version is vulnerable and the trigger pattern is present
in this config. Fixed in: 1.30.4, 1.31.3.
```

### 已打补丁的二进制文件

```
$ gixy --nginx-version=1.30.7 nginx.conf  # silent: current fixes are present
```

## 扩展数据库

在 `gixy/plugins/_nginx_cves_db.py` 的 `CVES` 中追加一个字典：

```python
{
    "id": "CVE-YYYY-NNNNN",
    "nickname": "Optional Nickname",
    "summary": "One-line issue description.",
    "severity": gixy.severity.HIGH,
    "advisory": "https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN",
    "vulnerable_oss": (((LOW_MAJOR, LOW_MINOR, LOW_PATCH),
                        (HIGH_MAJOR, HIGH_MINOR, HIGH_PATCH)),),
    "fixed_oss": ("X.Y.Z", "A.B.C"),
    "fixed_plus": ("R<N> P<M>",),
    "config_check": check_cve_YYYY_NNNNN,  # or None for binary-only CVEs
}
```

如果该 CVE 存在配置触发模式，请在旁边添加一个小型生成器函数 `check_cve_YYYY_NNNNN(root)`，为每次匹配产出 `(primary_directive, related_directive)` 对。

## 局限性

- **11 月条目的前提不等于漏洞可利用性证明。** Resolver 检查无法证明请求时
  主机名相同，也不读取 SSI 页面。静态 regex/map 捕获检查无法证明某个请求
  的精确捕获序列。这些报告无法确定 HTTP/2 连接资源紧张、特制协议流量、
  TLS 库支持、ASLR 绕过或实际 stream 后端路由；也不解析任意变量间接引用。

- **开源版版本匹配。** NGINX Plus 的 R 系列补丁模型需要按发布轨道设计专门的比较器；消息中仍会以纯文本形式提及 Plus 的修复版本，以便 Plus 运维人员手动应用。
- **CVE-2026-42945 模式检查只针对直接同级作用域**（与产生漏洞利用的、按上下文进行的脚本引擎编译保持一致）。如果 `rewrite` 位于 `if {}` 块内，而后续的 `set` 位于该 `if` 之外，则不会被标记。
- **满足前提不等于存在可利用的漏洞。** CVE-2026-97205 还要求 SSI 页面内容包含 `include virtual` 命令；gixy 不会检查这些文件。CVE-2026-93479 仍是基于版本的公告，并不证明存在可被利用的配置。
- **直接引用文件名。** CVE-2026-15176 检查的是词法层面的变量引用和生效的具名日志格式；对任意的变量间接引用和请求时的控制流并未完整建模。
- **目标身份。** 只有显式使用 `--nginx-version=auto` 才会检测本地二进制文件。否则请自行指定目标版本；仅凭配置无法确定二进制文件身份或供应商补丁。

--8<-- "zh/snippets/nginx-extras-cta.md"
