---
title: "OCSP Stapling Without Resolver"
description: "Enable a resolver alongside ssl_stapling on; otherwise nginx cannot fetch the OCSP response and stapling silently fails."
---

# OCSP Stapling Without Resolver

_Gixy Check ID: `ssl_stapling_without_resolver`_


When `ssl_stapling on;` is in effect for an SSL server but no `resolver` directive is reachable in scope, nginx has no way to look up the OCSP responder hostname. The stapling machinery silently falls back to "no stapled response," clients run their own OCSP queries, the TLS handshake adds round trips, and the security/performance gains of stapling are lost. nginx logs a warning to `error.log` at startup, but those warnings are easy to miss.

This is a pure configuration bug — there is no legitimate setup where you would enable `ssl_stapling` without configuring a `resolver`.

!!! note "Let's Encrypt certificates"
    If the certificate comes from Let's Encrypt, the fix is not to add a resolver — it is to remove the stapling directives entirely. Let's Encrypt shut its OCSP responders down on 2025-08-06 and no longer publishes an OCSP URL in its certificates. See [OCSP Stapling With a Let's Encrypt Certificate](ssl-stapling-letsencrypt.md).

## Bad Example

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    ssl_stapling on;
    ssl_stapling_verify on;
}
```

Or inherited from `http {}` without any server providing a resolver:

```nginx
http {
    ssl_stapling on;          # inherited by every server below

    server {
        listen 443 ssl;
        ssl_certificate     /etc/ssl/certs/example.com.pem;
        ssl_certificate_key /etc/ssl/private/example.com.key;
        # ← no resolver visible anywhere up the chain
    }
}
```

## Good Example

Put the resolver at `http` level so every SSL server inherits it:

```nginx
http {
    resolver 127.0.0.1 valid=300s ipv6=off;
    resolver_timeout 5s;

    ssl_stapling on;
    ssl_stapling_verify on;

    server {
        listen 443 ssl;
        server_name example.com;

        ssl_certificate     /etc/ssl/certs/example.com.pem;
        ssl_certificate_key /etc/ssl/private/example.com.key;
    }
}
```

Pair `ssl_stapling on` with `ssl_stapling_verify on` and a fast `resolver_timeout` so a slow OCSP lookup never stalls the handshake.

## What this check does not flag

- `ssl_stapling off;` — stapling is intentionally disabled, no resolver needed.
- Non-SSL servers (`listen 80;`) — stapling is irrelevant.
- A `server` block that overrides with `ssl_stapling off;` even when `http` enables it globally.
- Servers where a `resolver` is reachable in any enclosing scope, including via `include`.
