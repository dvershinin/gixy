---
title: "Static DNS Resolution in proxy_pass"
description: "Hostnames in proxy_pass resolve once at startup—configure resolver/resolve so dynamic backends keep working."
---

# Static DNS Resolution in proxy_pass

_Gixy Check ID: `missing_resolver`_


Detects `proxy_pass` (and related) configurations where hostnames are resolved only at nginx startup, potentially causing requests to be sent to stale IP addresses.

## Why it matters

When you use a hostname directly in `proxy_pass`:

```nginx
proxy_pass https://api.example.com;
```

Nginx resolves the DNS **once at startup** and caches that IP forever. If the IP changes (common with cloud load balancers, CDNs, or failover scenarios), nginx will continue sending traffic to the old IP until restarted.

This can cause:
- **Service outages** when backend IPs change
- **Security issues** if old IPs are reassigned to malicious actors
- **Load balancing failures** when using DNS-based load balancing

## Smart Detection: Inverse Logic

This plugin uses **inverse logic** for maximum coverage and security:

> Instead of trying to identify public domains (impossible without the [Public Suffix List](https://publicsuffix.org/)), we identify what's **DEFINITELY INTERNAL** and flag **EVERYTHING ELSE**.

This approach is superior because:
- ✅ **No external dependencies** - no need for PSL, tldextract, or any library
- ✅ **No hardcoded TLD list** that becomes outdated
- ✅ **New TLDs automatically flagged** - `.ai`, `.xyz`, `.whatever` all get caught
- ✅ **More secure** - false positives are better than false negatives for security tools
- ✅ **Future-proof** - works with any domain that will ever exist

### 🔥 Cloud Provider Detection (HIGH severity)
Automatically detects 50+ cloud provider patterns where IPs change frequently:
- **AWS**: ELB, CloudFront, API Gateway, Elastic Beanstalk, Lambda URLs, S3, Amplify, Global Accelerator
- **Google Cloud**: Cloud Run, Cloud Functions, App Engine, Firebase, Google APIs
- **Azure**: App Service, API Management, CDN, Traffic Manager, Front Door, Static Web Apps
- **Cloudflare**: Workers, Pages, R2
- **CDNs**: Akamai, Fastly, CDN77, StackPath, KeyCDN, BunnyCDN
- **PaaS**: Heroku, Vercel, Netlify, Railway, Render, Fly.io, Deno Deploy, Supabase, Neon, PlanetScale
- **Cloud**: DigitalOcean, Linode, Vultr, Scaleway, Hetzner, UpCloud

### 🐳 Container Orchestration Awareness
Automatically skips internal service discovery patterns:
- **Kubernetes**: `.svc.cluster.local`, `.pod.cluster.local`, `.default.svc`
- **Docker**: `.docker.internal`, `.docker.localhost`
- **Consul**: `.service.consul`, `.node.consul`, `.query.consul`
- **HashiCorp**: `.vault`, `.nomad`
- **Mesos/Marathon**: `.marathon.mesos`, `.dcos`
- **Rancher**: `.rancher.internal`
- **AWS Internal**: `.ec2.internal`, `.compute.internal`
- **OpenStack**: `.novalocal`, `.openstacklocal`

### 🎯 RFC-Compliant Reserved TLD Detection
Recognizes RFC 2606/6761/6762/7686 reserved TLDs:
- `.test`, `.example`, `.invalid` (RFC 2606)
- `.localhost` (RFC 6761)
- `.local` (RFC 6762 - mDNS/Bonjour)
- `.onion` (RFC 7686 - Tor)

### 🔍 Resolver Directive Checking
Detects when you use a variable but forgot to configure the `resolver` directive:

```nginx
# This WON'T re-resolve without a resolver directive!
set $backend api.example.com;
proxy_pass http://$backend;  # ← Plugin will warn about missing resolver
```

### 📦 Upstream Analysis
Checks upstream blocks for servers without the `resolve` parameter:

```nginx
upstream backend {
    server api.example.com;  # ← No 'resolve' = static DNS
}
```

## What triggers this check

| Pattern | Severity | Example |
|---------|----------|---------|
| Cloud provider endpoints | **HIGH** | `proxy_pass https://my-app.herokuapp.com;` |
| Public domain hostnames | MEDIUM | `proxy_pass https://api.example.com;` |
| Variable without resolver | MEDIUM | `set $x host.com; proxy_pass http://$x;` |
| Upstream without resolve | MEDIUM | `upstream { server host.com; }` |

## What doesn't trigger (false positives avoided)

- ✅ IP addresses (no DNS resolution needed)
- ✅ Unix sockets (`unix:/path/to/socket`)
- ✅ Internal domains (`.internal`, `.local`, `.lan`, `.corp`, `.home`, etc.)
- ✅ Single-label hostnames (`proxy_pass http://backend;`)
- ✅ Kubernetes services (`.svc.cluster.local`)
- ✅ Consul services (`.service.consul`)
- ✅ Docker internal (`.docker.internal`)
- ✅ URLs with variables AND resolver configured
- ✅ Upstream servers with `resolve` parameter

## Examples

### Bad: Cloud provider endpoint (HIGH severity)

```nginx
# CRITICAL: AWS ELB IPs change constantly!
location /api {
    proxy_pass https://my-app-123456789.us-east-1.elb.amazonaws.com;
}
```

### Bad: Static hostname (MEDIUM severity)

```nginx
# DNS resolved once at startup
location /api {
    proxy_pass https://api.example.com;
}
```

### Bad: Variable without resolver

```nginx
# Variable alone doesn't enable re-resolution!
set $backend api.example.com;
proxy_pass http://$backend;
```

### Bad: Upstream without resolve

```nginx
upstream backend {
    server api.example.com:8080;  # No resolve parameter
}

server {
    location / {
        proxy_pass http://backend;
    }
}
```

### Good: Variable with resolver

```nginx
resolver 127.0.0.1 valid=30s;

server {
    location /api {
        set $backend api.example.com;
        proxy_pass https://$backend;
    }
}
```

### Good: Upstream with resolve (nginx 1.27.3+)

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

### Good: Internal service (auto-skipped)

```nginx
# Kubernetes service - plugin knows this is internal
proxy_pass http://api-service.default.svc.cluster.local;
```

## Directives Checked

This plugin analyzes all proxy-related directives:
- `proxy_pass`
- `fastcgi_pass`
- `uwsgi_pass`
- `scgi_pass`
- `grpc_pass`

## Configuration

Disable this plugin in `.gixy.yml`:

```yaml
plugins:
  missing_resolver: false
```

## References

- [nginx resolver directive](https://nginx.org/en/docs/http/ngx_http_core_module.html#resolver)
- [nginx upstream server resolve parameter](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#server)
- [NGINX Blog: DNS Service Discovery](https://www.nginx.com/blog/dns-service-discovery-nginx-plus/)
