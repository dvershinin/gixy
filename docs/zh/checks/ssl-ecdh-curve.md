---
title: "导致 NGINX 无法启动的后量子 ssl_ecdh_curve"
description: "ssl_ecdh_curve 中未加 ? 前缀的后量子群会让 OpenSSL 拒绝整个列表，导致 NGINX 在 Debian 12、Ubuntu 24.04 和 RHEL 9 上拒绝启动。"
---

# 导致 NGINX 无法启动的后量子 `ssl_ecdh_curve`

_Gixy 检查 ID：`ssl_ecdh_curve`_

如今每一篇「为 nginx 添加后量子 TLS」的文章都以同一行结尾：

```nginx
ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;
```

把它复制到 OpenSSL 版本早于 3.5 的机器上，站点就会挂掉。不是「失去后量子支持」，
而是彻底挂掉。

## 为什么这是硬性故障而不是降级

nginx 会把该值直接交给 OpenSSL：

```c
/* src/event/ngx_event_openssl.c */
if (SSL_CTX_set1_curves_list(ssl->ctx, &conf->ecdh_curve...) == 0) {
    ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                  "SSL_CTX_set1_curves_list(\"%V\") failed", &conf->ecdh_curve);
    return NGX_ERROR;
}
```

两个特性叠加后果很糟：

1. **只要有一个群名未知，OpenSSL 就会拒绝整个列表**。不存在部分接受的情况——
   `X25519MLKEM768:X25519:prime256v1` 会整体失败，尽管其中两个群是普遍支持的。
2. **nginx 以 `NGX_LOG_EMERG` 级别记录该错误**并返回失败，因此主进程根本无法完成
   配置解析。这是启动失败，而不是单个连接层面的回退。

已在 OpenSSL 3.6.3 上验证：

```console
$ openssl s_client -groups bogusgroup -connect 127.0.0.1:1
Call to SSL_CONF_cmd(-groups, bogusgroup) failed

$ openssl s_client -groups '?bogusgroup:X25519' -connect 127.0.0.1:1
connect:errno=61          # 列表已被接受；失败的只是 TCP 连接
```

`X25519MLKEM768` 及同类群是在 **OpenSSL 3.5** 中引入的。而运行生产环境 nginx
最多的那些发行版所附带的版本更旧：

| 发行版 | OpenSSL | `X25519MLKEM768` |
|---|---|---|
| Debian 12 (bookworm) | 3.0 | ✗ nginx 无法启动 |
| Ubuntu 24.04 LTS | 3.0 | ✗ nginx 无法启动 |
| RHEL / AlmaLinux / Rocky 9 | 3.2 | ✗ nginx 无法启动 |

在写下任何后量子群名之前，先用 `openssl version` 确认你实际使用的版本；
`openssl list -tls-groups`（OpenSSL 3.x）会列出所链接的库真正接受的群集合。

同样的问题也适用于旧版 BoringSSL 构建和 2024 年前后的指南所使用的标准化之前的
`X25519Kyber768Draft00` 名称。

## 错误示例

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    # 只要有一个未知名称，主进程就会拒绝启动
    ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;
}
```

## 正确示例

给后量子群加上 `?` 前缀。这样 OpenSSL 会跳过它不认识的名称，而不是让整个列表失败：

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    ssl_ecdh_curve ?X25519MLKEM768:X25519:prime256v1;
}
```

装有 OpenSSL 3.5+ 的机器会协商出 `X25519MLKEM768`；较旧的机器则会静默回退到
`X25519` 并继续提供服务。

## `?` 前缀本身也有版本门槛

`?` 是在 **OpenSSL 3.3** 中加入的。在 OpenSSL 3.0 和 3.2 上，`?X25519MLKEM768`
本身就是一个无法解析的群名，会以完全相同的方式失败。因此：

- **OpenSSL 3.5+** —— 可以直接列出后量子群，或加上 `?`。
- **OpenSSL 3.3 / 3.4** —— 使用 `?`，让配置向前兼容。
- **OpenSSL 3.0 / 3.2（Debian 12、Ubuntu 24.04、RHEL 9）** —— 完全不要写后量子
  群。保留 `ssl_ecdh_curve auto;`（nginx 默认值），或只列出经典曲线。

如果同一份配置要下发到版本混杂的服务器群，请在构建时决定是否启用该指令，而不要
指望 `?` 能救你。

## 本检查不会标记的情况

- `ssl_ecdh_curve auto;` —— nginx 的默认值；群列表由 OpenSSL 选择。
- 仅使用经典曲线（`X25519:prime256v1:secp384r1`）。
- 已经带有 `?` 前缀的后量子群。
