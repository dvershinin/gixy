---
title: "ssl_ecdh_curve 与 NGINX 后量子密钥交换"
description: "Gixy 检测会让 nginx 无法启动、悄然禁用 X25519MLKEM768 后量子密钥交换，或把它排在 X25519 之后的 ssl_ecdh_curve 列表。"
---

# `ssl_ecdh_curve` 与后量子密钥交换

_Gixy 检查 ID：`ssl_ecdh_curve`_

自 OpenSSL 3.5 提供 `X25519MLKEM768` 后量子混合群以来，这条一行的指令有三种不同的出错方式：

| 问题 | 严重性 | 示例 |
|---|---|---|
| 后量子群缺少 `?` 前缀 | HIGH | `X25519MLKEM768:X25519:prime256v1` |
| 只有经典群 | MEDIUM | `X25519:secp384r1:prime256v1` |
| 后量子群与经典群处于同一层级 | LOW | `?X25519MLKEM768:X25519:prime256v1` |

对于链接 OpenSSL 3.5+ 的 nginx，最干净的做法是**完全不设置该指令**。如果必须固定列表，请把混合群放在单独的最高层级：

```nginx
ssl_ecdh_curve ?X25519MLKEM768/X25519:prime256v1;
```

## HIGH：导致 nginx 无法启动的后量子群

nginx 会把值直接交给 OpenSSL：

```c
/* src/event/ngx_event_openssl.c */
if (SSL_CTX_set1_curves_list(ssl->ctx, &conf->ecdh_curve...) == 0) {
    ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                  "SSL_CTX_set1_curves_list(\"%V\") failed", &conf->ecdh_curve);
    return NGX_ERROR;
}
```

两个特性叠加后很糟糕：

1. 只要有一个群名未知，**OpenSSL 就会拒绝整个列表**。不存在部分接受：`X25519MLKEM768:X25519:prime256v1` 会整体失败，尽管其中两个群处处可用。
2. **nginx 以 `NGX_LOG_EMERG` 级别记录**并返回错误，主进程无法完成配置。这是启动失败，而不是单个连接的回退。

`X25519MLKEM768` 等群在 **OpenSSL 3.5** 中加入。各发行版自带的版本（2026 年 11 月核实）：

| 发行版 | 系统 OpenSSL | `X25519MLKEM768` |
|---|---|---|
| Debian 13 (trixie) | 3.5 | ✓ |
| RHEL / AlmaLinux / Rocky 9 (9.8) | 3.5 | ✓ |
| Debian 12 (bookworm) | 3.0 | ✗ nginx 无法启动 |
| Ubuntu 24.04 / 22.04 LTS | 3.0 | ✗ nginx 无法启动 |
| RHEL / AlmaLinux / Rocky 8 | 1.1.1 | ✗ nginx 无法启动 |

关键在于 *nginx* 链接的库，而不是系统库：用 `nginx -V 2>&1 | grep "built with"` 查看。[GetPageSpeed 的 NGINX 软件包](https://www.getpagespeed.com/repo-subscribe)在上述所有平台上都链接 OpenSSL 3.5 LTS，包括系统只有 3.0 和 1.1.1 的平台。

旧版基于 BoringSSL 的构建和 2024 年的教程中使用的标准化前名称 `X25519Kyber768Draft00` 也会以同样方式失败。

### `?` 前缀本身的版本限制

`?` 让 OpenSSL 跳过不认识的群名，而不是让整个列表失败。它在 **OpenSSL 3.3** 中加入：在 OpenSSL 3.0 和 3.2 上，`?X25519MLKEM768` 本身就是无法解析的名称，同样会失败。下文的层级分隔符 `/` 需要 OpenSSL 3.5。因此：

- **OpenSSL 3.5+**：`?X25519MLKEM768/X25519:prime256v1`，或不设置指令。
- **OpenSSL 3.3 / 3.4**：没有 ML-KEM。`?` 能防止列表失败，但没有可协商的后量子群。
- **OpenSSL 3.0 / 3.2 / 1.1.1**：完全不要写后量子群。不设置该指令，或只列出经典曲线。

## MEDIUM：只有经典群

```nginx
# ML-KEM 之前的加固建议。在 OpenSSL 3.5+ 上它会关闭后量子密钥交换。
ssl_ecdh_curve X25519:secp384r1:prime256v1;
```

显式列表会**替换** OpenSSL 的默认值，而不是在其基础上追加。OpenSSL 3.5+ 的默认列表以 `X25519MLKEM768` 开头，只含经典群的列表会让所有客户端（包括浏览器）都无法使用混合群。`nginx -t` 照常通过，日志里什么也没有，浏览器的锁形图标也一样。

在任何 OpenSSL 版本上都安全的修复是删除该指令，沿用库的默认值。在 OpenSSL 3.5+ 上也可以在前面加一个后量子层级：`?X25519MLKEM768/X25519:secp384r1:prime256v1`。

## LOW：后量子群与经典群处于同一层级

OpenSSL 3.5 把群列表视为**偏好层级**：`:` 把群合并为同一层级，`/` 开始下一个更低的层级。在同一层级内，服务器采用客户端最先发送的密钥份额（key share）；只有在层级之间，它才会坚持更强的群。

TLS 1.3 客户端可以提供某个群而不为它发送密钥份额。面对 `?X25519MLKEM768:X25519:prime256v1`，一个提供混合群但先发送 X25519 份额的客户端会协商出经典的 X25519。改用 `?X25519MLKEM768/X25519:prime256v1` 后，服务器会回复 HelloRetryRequest 索要混合群份额，代价是多一次往返。

在 nginx 1.30 + OpenSSL 3.5.9 上的实测：

| 客户端密钥份额 | `A:B`（同一层级） | `A/B`（两个层级） |
|---|---|---|
| 混合群, X25519 | `X25519MLKEM768` | `X25519MLKEM768` |
| X25519, 混合群 | `X25519` | `X25519MLKEM768` |
| 仅 X25519，提供混合群 | `X25519` | `X25519MLKEM768`（HRR） |

当前的 Chrome、Firefox、curl/OpenSSL 3.5、Go 和 Java 都会发送混合群份额，两种写法下都能协商出 `X25519MLKEM768`。层级只对先发送 X25519 的客户端有影响，例如 Cloudflare 在 2026 年推出 Automatic Key Exchange 之前的回源连接。因此该问题的严重性为 LOW。

## 本检查不会标记的情况

- 没有 `ssl_ecdh_curve`，或 `ssl_ecdh_curve auto;`（nginx 默认值）。
- 基于 OpenSSL `DEFAULT` 关键字的列表，例如 `DEFAULT:-X448`。
- 带 `?` 前缀并位于单独最高层级的后量子群。
