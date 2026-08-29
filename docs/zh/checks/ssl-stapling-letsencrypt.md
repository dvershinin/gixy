---
title: "对 Let's Encrypt 证书启用 OCSP Stapling"
description: "Let's Encrypt 已于 2025-08-06 关闭其 OCSP 响应器，因此对 certbot 证书使用 ssl_stapling on 不会装订任何内容，属于无效配置。"
---

# 对 Let's Encrypt 证书启用 OCSP Stapling

_Gixy 检查 ID：`ssl_stapling_letsencrypt`_

几乎每一篇 2025 年之前写成的 nginx TLS 指南，都以同样的三行结尾：

```nginx
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;
```

对于 Let's Encrypt 证书，这几行现在完全不起作用。

## 发生了什么变化

Let's Encrypt 于 2024 年 7 月宣布终止 OCSP，并分阶段执行：

- **2025 年初** —— 新签发的证书不再在 Authority Information Access 扩展中携带
  OCSP 响应器 URL。
- **2025-08-06** —— OCSP 响应器被彻底关闭。

OCSP stapling 的工作方式是：nginx 从证书中读取响应器 URL，再向 CA 获取一份带签名
的状态。证书里没有该 URL，就无从获取，因此 `ssl_stapling on` 永久成为空操作。
Let's Encrypt 的吊销机制依靠证书的短有效期，以及浏览器通过聚合服务（CRLite、
CRLSets）消费的 CRL，而不是客户端去查询响应器。

这属于无效配置，而不是漏洞——所以严重级别为低。但仍然值得清除：它会在启动时产生
日志噪音，会随着配置被从服务器复制而一直流传下去，还会误导下一个阅读配置的人，
让他以为吊销检查正在进行。

## 错误示例

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate         /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key     /etc/letsencrypt/live/example.com/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;

    resolver 127.0.0.1 valid=300s;

    ssl_stapling on;         # 没有任何内容可装订
    ssl_stapling_verify on;
}
```

## 正确示例

对使用 Let's Encrypt 的主机，直接删掉 stapling 配置块：

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
}
```

在仍然有意义的地方保留 stapling —— 也就是仍在运行 OCSP 响应器的商业 CA：

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate         /etc/ssl/certs/example.com.pem;
    ssl_certificate_key     /etc/ssl/private/example.com.key;
    ssl_trusted_certificate /etc/ssl/certs/example.com.chain.pem;

    resolver 127.0.0.1 valid=300s;
    resolver_timeout 5s;

    ssl_stapling on;
    ssl_stapling_verify on;
}
```

关于真正启用 stapling 时始终适用的 resolver 要求，参见
[没有 resolver 的 OCSP Stapling](ssl-stapling-without-resolver.md)。

## 本检查不会标记的情况

- `ssl_stapling off;`，或在 `http` 层设为 `on` 后被 server 覆盖的情况。
- `/etc/letsencrypt/` 之外的证书 —— 包括其 CA 仍在运行 OCSP 的其他 ACME 客户端。
- 非 SSL 的 server。

## 误报

本检查依据 certbot 的路径前缀 `/etc/letsencrypt/` 判断。把非 Let's Encrypt 的证书
放在该目录下并不常见，但确实可能，因此该发现的措辞是「看起来是」，级别定为低。
可以这样核实：

```console
$ openssl x509 -in /etc/letsencrypt/live/example.com/cert.pem -noout -ocsp_uri
```

输出为空就说明没有任何响应器可供装订，无论签发方是哪家 CA。
