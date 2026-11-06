---
title: "ssl_ecdh_curve and Post-Quantum Key Exchange in NGINX"
description: "Gixy flags ssl_ecdh_curve lists that stop nginx from starting, silently disable X25519MLKEM768 post-quantum key exchange, or rank it no higher than X25519."
---

# `ssl_ecdh_curve` and Post-Quantum Key Exchange

_Gixy Check ID: `ssl_ecdh_curve`_

`ssl_ecdh_curve` is a one-line directive with three distinct ways to go wrong
now that OpenSSL 3.5 ships the `X25519MLKEM768` post-quantum hybrid:

| Finding | Severity | Example |
|---|---|---|
| Post-quantum group without `?` | HIGH | `X25519MLKEM768:X25519:prime256v1` |
| Classical groups only | MEDIUM | `X25519:secp384r1:prime256v1` |
| Post-quantum shares a tier with classical | LOW | `?X25519MLKEM768:X25519:prime256v1` |

The clean form, on nginx linked against OpenSSL 3.5+, is to **leave the
directive unset**. If you pin the list, give the hybrid its own top tier:

```nginx
ssl_ecdh_curve ?X25519MLKEM768/X25519:prime256v1;
```

## HIGH: a post-quantum group that stops nginx from starting

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
   is no partial acceptance: `X25519MLKEM768:X25519:prime256v1` fails as a
   whole, even though two of the three groups are universally supported.
2. **nginx logs that at `NGX_LOG_EMERG`** and returns an error, so the master
   process never finishes configuration. This is a startup failure, not a
   per-connection fallback.

`X25519MLKEM768` and friends landed in **OpenSSL 3.5**. What the distribution
packages ship (checked November 2026):

| Distribution | System OpenSSL | `X25519MLKEM768` |
|---|---|---|
| Debian 13 (trixie) | 3.5 | ✓ |
| RHEL / AlmaLinux / Rocky 9 (9.8) | 3.5 | ✓ |
| Debian 12 (bookworm) | 3.0 | ✗ nginx will not start |
| Ubuntu 24.04 / 22.04 LTS | 3.0 | ✗ nginx will not start |
| RHEL / AlmaLinux / Rocky 8 | 1.1.1 | ✗ nginx will not start |

What counts is the library *nginx* links, not the system one: check
`nginx -V 2>&1 | grep "built with"`. [GetPageSpeed NGINX
packages](https://www.getpagespeed.com/repo-subscribe) link an OpenSSL 3.5 LTS
build on every platform above, including the 3.0 and 1.1.1 ones.

The pre-standard `X25519Kyber768Draft00` names that older BoringSSL-based
builds and 2024-era guides use fail the same way.

### The `?` prefix, and its own version gate

`?` tells OpenSSL to skip a group name it does not recognise instead of failing
the list. It was added in **OpenSSL 3.3**: on OpenSSL 3.0 and 3.2,
`?X25519MLKEM768` is itself an unparseable name and fails the same way. The `/`
tier separator below needs OpenSSL 3.5. So:

- **OpenSSL 3.5+**: `?X25519MLKEM768/X25519:prime256v1`, or no directive.
- **OpenSSL 3.3 / 3.4**: no ML-KEM exists. `?` keeps a post-quantum list from
  failing, but there is nothing post-quantum to negotiate.
- **OpenSSL 3.0 / 3.2 / 1.1.1**: do not name post-quantum groups at all. Leave
  the directive unset, or list only classical curves.

## MEDIUM: classical groups only

```nginx
# The pre-ML-KEM hardening advice. On OpenSSL 3.5+ it turns post-quantum off.
ssl_ecdh_curve X25519:secp384r1:prime256v1;
```

An explicit list **replaces** OpenSSL's default instead of extending it. On
OpenSSL 3.5+, whose default leads with `X25519MLKEM768`, a list of classical
groups refuses the hybrid for every client, browsers included. `nginx -t`
passes, nothing is logged, and the padlock looks the same.

The fix that is safe on every OpenSSL version is to delete the directive and
follow the library default. On OpenSSL 3.5+ you can instead prepend a
post-quantum tier: `?X25519MLKEM768/X25519:secp384r1:prime256v1`.

## LOW: post-quantum sharing a tier with classical groups

OpenSSL 3.5 reads the group list as **preference tiers**: `:` joins groups in
one tier and `/` starts the next, lower one. Inside a tier, the server takes
the key share the client sent first; only between tiers does it insist on the
stronger group.

A TLS 1.3 client can offer a group without sending a key share for it. Against
`?X25519MLKEM768:X25519:prime256v1`, a client that offers the hybrid but leads
with an X25519 key share negotiates classical X25519. With
`?X25519MLKEM768/X25519:prime256v1` the server answers with a HelloRetryRequest
for the hybrid share instead, at the cost of one round trip.

Measured against nginx 1.30 with OpenSSL 3.5.9:

| Client key shares | `A:B` (one tier) | `A/B` (two tiers) |
|---|---|---|
| hybrid, X25519 | `X25519MLKEM768` | `X25519MLKEM768` |
| X25519, hybrid | `X25519` | `X25519MLKEM768` |
| X25519 only, hybrid offered | `X25519` | `X25519MLKEM768` (HRR) |

Current Chrome, Firefox, curl/OpenSSL 3.5, Go and Java all send a hybrid key
share and negotiate `X25519MLKEM768` under either form. The tier matters for
clients that lead with X25519, such as Cloudflare's origin connections before
its 2026 Automatic Key Exchange rollout. That is why this finding is LOW.

## What this check does not flag

- No `ssl_ecdh_curve` at all, or `ssl_ecdh_curve auto;` (the nginx default).
- Lists built on OpenSSL's `DEFAULT` keyword, such as `DEFAULT:-X448`.
- Post-quantum groups that carry the `?` prefix in their own top tier.
