---
title: "proxy_pass 中的静态 DNS 解析"
description: "proxy_pass 中的主机名只在启动时解析一次——配置 resolver/resolve 以确保动态后端继续工作。"
---

# proxy_pass 中的静态 DNS 解析

_Gixy 检查 ID：`missing_resolver`_


检测 `proxy_pass`（及相关指令）配置，其中主机名仅在 nginx 启动时解析，可能导致请求被发送到过时的 IP 地址。

## 为什么这很重要

当您在 `proxy_pass` 中直接使用主机名时：

```nginx
proxy_pass https://api.example.com;
```

Nginx **在启动时只解析一次** DNS 并永久缓存该 IP。如果 IP 更改（这在云负载均衡器、CDN 或故障转移场景中很常见），nginx 将继续向旧 IP 发送流量，直到重启。

这可能导致：
- 当后端 IP 更改时**服务中断**
- 如果旧 IP 被分配给恶意行为者，则存在**安全问题**
- 使用基于 DNS 的负载均衡时**负载均衡失败**

## 智能检测：反向逻辑

此插件使用**反向逻辑**以获得最大覆盖范围和安全性：

> 我们不是尝试识别公共域（没有 [Public Suffix List](https://publicsuffix.org/) 是不可能的），而是识别什么是**绝对内部的**，并标记**其他所有内容**。

这种方法更好，因为：
- ✅ **无外部依赖** — 不需要 PSL、tldextract 或任何库
- ✅ **无硬编码的 TLD 列表**会过时
- ✅ **新 TLD 自动标记** — `.ai`、`.xyz`、`.whatever` 都会被捕获
- ✅ **更安全** — 对于安全工具，误报比漏报更好
- ✅ **面向未来** — 适用于任何将来存在的域

### 🔥 云提供商检测（高严重级别）
自动检测 50 多种 IP 频繁更改的云提供商模式：
- **AWS**：ELB、CloudFront、API Gateway、Elastic Beanstalk、Lambda URLs、S3、Amplify、Global Accelerator
- **Google Cloud**：Cloud Run、Cloud Functions、App Engine、Firebase、Google APIs
- **Azure**：App Service、API Management、CDN、Traffic Manager、Front Door、Static Web Apps
- **Cloudflare**：Workers、Pages、R2
- **CDN**：Akamai、Fastly、CDN77、StackPath、KeyCDN、BunnyCDN
- **PaaS**：Heroku、Vercel、Netlify、Railway、Render、Fly.io、Deno Deploy、Supabase、Neon、PlanetScale
- **Cloud**：DigitalOcean、Linode、Vultr、Scaleway、Hetzner、UpCloud

### 🐳 容器编排感知
自动跳过内部服务发现模式：
- **Kubernetes**：`.svc.cluster.local`、`.pod.cluster.local`、`.default.svc`
- **Docker**：`.docker.internal`、`.docker.localhost`
- **Consul**：`.service.consul`、`.node.consul`、`.query.consul`
- **HashiCorp**：`.vault`、`.nomad`
- **Mesos/Marathon**：`.marathon.mesos`、`.dcos`
- **Rancher**：`.rancher.internal`
- **AWS Internal**：`.ec2.internal`、`.compute.internal`
- **OpenStack**：`.novalocal`、`.openstacklocal`

### 🎯 符合 RFC 的保留 TLD 检测
识别 RFC 2606/6761/6762/7686 保留 TLD：
- `.test`、`.example`、`.invalid`（RFC 2606）
- `.localhost`（RFC 6761）
- `.local`（RFC 6762 — mDNS/Bonjour）
- `.onion`（RFC 7686 — Tor）

### 🔍 Resolver 指令检查
检测当您使用变量但忘记配置 `resolver` 指令的情况：

```nginx
# 没有 resolver 指令，这不会重新解析！
set $backend api.example.com;
proxy_pass http://$backend;  # ← 插件会警告缺少 resolver
```

### 📦 Upstream 分析
检查 upstream 块中没有 `resolve` 参数的服务器：

```nginx
upstream backend {
    server api.example.com;  # ← 没有 'resolve' = 静态 DNS
}
```

## 触发此检查的条件

| 模式 | 严重级别 | 示例 |
|---------|----------|---------|
| 云提供商端点 | **高** | `proxy_pass https://my-app.herokuapp.com;` |
| 公共域主机名 | 中等 | `proxy_pass https://api.example.com;` |
| 没有 resolver 的变量 | 中等 | `set $x host.com; proxy_pass http://$x;` |
| 没有 resolve 的 Upstream | 中等 | `upstream { server host.com; }` |

## 不触发的情况（避免的误报）

- ✅ IP 地址（不需要 DNS 解析）
- ✅ Unix 套接字（`unix:/path/to/socket`）
- ✅ 内部域（`.internal`、`.local`、`.lan`、`.corp`、`.home` 等）
- ✅ 单标签主机名（`proxy_pass http://backend;`）
- ✅ Kubernetes 服务（`.svc.cluster.local`）
- ✅ Consul 服务（`.service.consul`）
- ✅ Docker internal（`.docker.internal`）
- ✅ 带变量且配置了 resolver 的 URL
- ✅ 带 `resolve` 参数的 upstream 服务器

## 示例

### 错误：云提供商端点（高严重级别）

```nginx
# 严重：AWS ELB IP 经常变化！
location /api {
    proxy_pass https://my-app-123456789.us-east-1.elb.amazonaws.com;
}
```

### 错误：静态主机名（中等严重级别）

```nginx
# DNS 在启动时只解析一次
location /api {
    proxy_pass https://api.example.com;
}
```

### 错误：没有 resolver 的变量

```nginx
# 仅变量不能启用重新解析！
set $backend api.example.com;
proxy_pass http://$backend;
```

### 错误：没有 resolve 的 Upstream

```nginx
upstream backend {
    server api.example.com:8080;  # 没有 resolve 参数
}

server {
    location / {
        proxy_pass http://backend;
    }
}
```

### 正确：带 resolver 的变量

```nginx
resolver 127.0.0.1 valid=30s;

server {
    location /api {
        set $backend api.example.com;
        proxy_pass https://$backend;
    }
}
```

### 正确：带 resolve 的 Upstream（nginx 1.27.3+）

```nginx
resolver 127.0.0.1;

upstream backend {
    server api.example.com:8080 resolve;
}

server {
    location / {
        proxy_pass http://backend;
    }
}
```

### 正确：内部服务（自动跳过）

```nginx
# Kubernetes 服务 — 插件知道这是内部的
proxy_pass http://api-service.default.svc.cluster.local;
```

## 检查的指令

此插件分析所有与代理相关的指令：
- `proxy_pass`
- `fastcgi_pass`
- `uwsgi_pass`
- `scgi_pass`
- `grpc_pass`

## 配置

在 `.gixy.yml` 中禁用此插件：

```yaml
plugins:
  missing_resolver: false
```

## 参考资料

- [nginx resolver 指令](https://nginx.org/en/docs/http/ngx_http_core_module.html#resolver)
- [nginx upstream server resolve 参数](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#server)
- [NGINX 博客：DNS 服务发现](https://www.nginx.com/blog/dns-service-discovery-nginx-plus/)
