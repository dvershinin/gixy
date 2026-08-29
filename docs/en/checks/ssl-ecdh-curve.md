---
title: "Post-Quantum ssl_ecdh_curve That Stops NGINX From Starting"
description: "A post-quantum group in ssl_ecdh_curve without the ? prefix makes OpenSSL reject the whole list and nginx refuse to start on Debian 12, Ubuntu 24.04 and RHEL 9."
---

# Post-Quantum `ssl_ecdh_curve` That Stops NGINX From Starting

_Gixy Check ID: `ssl_ecdh_curve`_

Every "add post-quantum TLS to nginx" post now ends with the same line:

```nginx
ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;
```

Copy that onto a box whose OpenSSL predates 3.5 and the site goes down. Not
"loses post-quantum support" — down.

## Why it is a hard outage, not a downgrade

nginx hands the value straight to OpenSSL:

```c
/* src/event/ngx_event_openssl.c */
if (SSL_CTX_set1_curves_list(ssl->ctx, &conf->ecdh_curve...) == 0) {
    ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                  "SSL_CTX_set1_curves_list(\"%V\") failed", &conf->ecdh_curve);
    return NGX_ERROR;
}
```

Two properties combine badly:

1. **OpenSSL rejects the entire list** if a single group name is unknown. There
   is no partial acceptance — `X25519MLKEM768:X25519:prime256v1` fails as a
   whole, even though two of the three groups are universally supported.
2. **nginx logs that at `NGX_LOG_EMERG`** and returns an error, so the master
   process never finishes configuration. This is a startup failure, not a
   per-connection fallback.

Verified against OpenSSL 3.6.3:

```console
$ openssl s_client -groups bogusgroup -connect 127.0.0.1:1
Call to SSL_CONF_cmd(-groups, bogusgroup) failed

$ openssl s_client -groups '?bogusgroup:X25519' -connect 127.0.0.1:1
connect:errno=61          # list accepted; only the TCP connect failed
```

`X25519MLKEM768` and friends landed in **OpenSSL 3.5**. The distributions most
production nginx runs on ship older:

| Distribution | OpenSSL | `X25519MLKEM768` |
|---|---|---|
| Debian 12 (bookworm) | 3.0 | ✗ nginx will not start |
| Ubuntu 24.04 LTS | 3.0 | ✗ nginx will not start |
| RHEL / AlmaLinux / Rocky 9 | 3.2 | ✗ nginx will not start |

Check what you actually have with `openssl version` before naming any
post-quantum group; `openssl list -tls-groups` (OpenSSL 3.x) shows the exact set
the linked library will accept.

The same applies to the pre-standard `X25519Kyber768Draft00` names that older
BoringSSL-based builds and 2024-era guides use.

## Bad Example

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    # One unknown name and the master process refuses to start
    ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;
}
```

## Good Example

Prefix the post-quantum groups with `?`. OpenSSL then skips names it does not
recognise instead of failing the list:

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    ssl_ecdh_curve ?X25519MLKEM768:X25519:prime256v1;
}
```

A box with OpenSSL 3.5+ negotiates `X25519MLKEM768`; an older one quietly falls
back to `X25519` and keeps serving.

## The `?` prefix has its own version gate

`?` was added in **OpenSSL 3.3**. On OpenSSL 3.0 and 3.2, `?X25519MLKEM768` is
itself an unparseable group name and fails exactly the same way. So:

- **OpenSSL 3.5+** — list post-quantum groups directly, or with `?`.
- **OpenSSL 3.3 / 3.4** — use `?` so the config is forward-compatible.
- **OpenSSL 3.0 / 3.2 (Debian 12, Ubuntu 24.04, RHEL 9)** — do not name
  post-quantum groups at all. Leave `ssl_ecdh_curve auto;` (the default) or
  list only classical curves.

If one config is deployed to a mixed fleet, gate the directive at build time
rather than assuming `?` saves you.

## What this check does not flag

- `ssl_ecdh_curve auto;` — the nginx default; OpenSSL picks the group list.
- Classical curves only (`X25519:prime256v1:secp384r1`).
- Post-quantum groups that already carry the `?` prefix.
