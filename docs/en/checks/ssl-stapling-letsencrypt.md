---
title: "OCSP Stapling With a Let's Encrypt Certificate"
description: "Let's Encrypt retired its OCSP responders on 2025-08-06, so ssl_stapling on with a certbot certificate staples nothing and is dead configuration."
---

# OCSP Stapling With a Let's Encrypt Certificate

_Gixy Check ID: `ssl_stapling_letsencrypt`_

Nearly every nginx TLS guide written before 2025 ends with the same three lines:

```nginx
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;
```

For a Let's Encrypt certificate, those lines now do nothing at all.

## What changed

Let's Encrypt announced the end of OCSP in July 2024 and executed it in stages:

- **Early 2025** — new certificates stopped carrying an OCSP responder URL in
  their Authority Information Access extension.
- **2025-08-06** — the OCSP responders were switched off entirely.

OCSP stapling works by nginx reading the responder URL out of the certificate
and fetching a signed status from the CA. With no URL in the certificate there
is nothing to fetch, so `ssl_stapling on` is a permanent no-op. Revocation for
Let's Encrypt is handled by short certificate lifetimes and by CRLs consumed
through browser aggregators (CRLite, CRLSets), not by clients querying a
responder.

This is dead configuration, not a vulnerability — hence the low severity. It is
still worth removing: it produces startup log noise, it survives into every
config copied from the server, and it misleads whoever reads it next into
thinking revocation checking is happening.

## Bad Example

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate         /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key     /etc/letsencrypt/live/example.com/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;

    resolver 127.0.0.1 valid=300s;

    ssl_stapling on;         # nothing to staple
    ssl_stapling_verify on;
}
```

## Good Example

Drop the stapling block for Let's Encrypt hosts:

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
}
```

Keep stapling where it still buys something — a commercial CA that runs an OCSP
responder:

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

See [OCSP Stapling Without Resolver](ssl-stapling-without-resolver.md) for the
resolver requirement that applies whenever stapling is genuinely in use.

## What this check does not flag

- `ssl_stapling off;`, or a server that overrides an `http`-level `on`.
- Certificates outside `/etc/letsencrypt/` — including other ACME clients whose
  CA still runs OCSP.
- Non-SSL servers.

## False positives

The check keys on the certbot path prefix `/etc/letsencrypt/`. A non-Let's
Encrypt certificate stored under that directory is unusual but possible, which
is why the finding is worded as "appears to be" and rated low. Verify with:

```console
$ openssl x509 -in /etc/letsencrypt/live/example.com/cert.pem -noout -ocsp_uri
```

Empty output means there is no responder to staple from, whatever the CA.
