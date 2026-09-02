---
title: "add_header Redefinition Pitfalls"
description: "Prevent parent headers from vanishing in nested blocks. Keep security headers like CSP and X-Frame-Options intact when adding new ones."
---

# Redefining Response Headers by add_header Directive

_Gixy Check ID: `add_header_redefinition`_


Unfortunately, many people don't know how the inheritance of directives works. Most often this leads to misuse of the `add_header` directive while trying to add a new response header on the nested level.
This feature is mentioned in Nginx [docs](https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header):
> There could be several `add_header` directives. These directives are inherited from the previous level if and only if there are no `add_header` directives defined on the current level.

The logic is quite simple: if you set headers at one level (for example, in `server` section) and then at a lower level (let's say `location`) you set some other headers, then the first headers will be discarded.

It's easy to check:
  - Configuration:
```nginx
server {
  listen 80;
  add_header X-Frame-Options "DENY" always;
  location / {
      return 200 "index";
  }

  location /new-headers {
    # Add special cache control
    add_header Cache-Control "no-cache, no-store, max-age=0, must-revalidate" always;
    add_header Pragma "no-cache" always;

    return 200 "new-headers";
  }
}
```
  - Request to location `/` (`X-Frame-Options` header is in server response):
```http
GET / HTTP/1.0

HTTP/1.1 200 OK
Server: nginx/1.10.2
Date: Mon, 09 Jan 2017 19:28:33 GMT
Content-Type: application/octet-stream
Content-Length: 5
Connection: close
X-Frame-Options: DENY

index
```
  - Request to location `/new-headers` (headers `Cache-Control` and `Pragma` are present, but there's no `X-Frame-Options`):
```http
GET /new-headers HTTP/1.0


HTTP/1.1 200 OK
Server: nginx/1.10.2
Date: Mon, 09 Jan 2017 19:29:46 GMT
Content-Type: application/octet-stream
Content-Length: 11
Connection: close
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache

new-headers
```

## Severity Classification

This plugin uses **intelligent value-aware severity classification** to minimize false positives while catching real security issues.

### MEDIUM Severity (Security-Critical)

Triggered when dropping headers that provide **actual security protection**:

#### Always-Secure Headers
These headers are security-critical regardless of their value:

| Header | Purpose |
|--------|---------|
| `Content-Security-Policy` | Prevents XSS, code injection |
| `Strict-Transport-Security` | Forces HTTPS |
| `X-Frame-Options` | Prevents clickjacking |
| `X-Content-Type-Options` | Prevents MIME sniffing |
| `Referrer-Policy` | Controls referrer leakage |
| `Permissions-Policy` | Restricts browser features |
| `Cross-Origin-*` | Cross-origin isolation |

#### Value-Aware Headers
For some headers, the **value determines security intent**:

| Header | Security-Protective Values | Non-Security Values |
|--------|---------------------------|---------------------|
| `Cache-Control` | `no-store`, `no-cache`, `private`, `must-revalidate` | `public`, `max-age=N` |
| `Pragma` | `no-cache` | Other values |
| `Expires` | `0`, `-1`, `1970` dates | Future dates |
| `Content-Disposition` | `attachment` | `inline` |
| `X-Download-Options` | `noopen` | Other values |

**Example:** Dropping `Cache-Control: no-store` is MEDIUM severity (security regression), but dropping `Cache-Control: public, max-age=3600` is LOW severity (just a caching optimization change).

### LOW Severity (Non-Security)

Triggered when dropping headers that are not security-protective, such as:

- Custom headers (`X-Custom-Header`)
- Performance headers (`Cache-Control: public`)
- Informational headers

## What can I do?

There are several ways to solve this problem:

### 1. Use `add_header_inherit` (nginx 1.29.3+)

Starting with nginx 1.29.3, you can use the `add_header_inherit` directive to inherit headers from parent levels:

```nginx
server {
    listen 80;
    add_header X-Frame-Options "DENY" always;

    location /new-headers {
        add_header_inherit merge;  # Append X-Frame-Options from server
        add_header Cache-Control "no-cache" always;
        return 200 "new-headers";
    }
}
```

Only `merge` fixes the redefinition trap. `on` is the default behavior and still
inherits parent headers only when the current level declares no headers of its own;
`off` disables inheritance. This is the cleanest solution if you're running nginx
1.29.3 or later.

The corresponding trailer directives use the same rules: use
`add_trailer_inherit merge;` when nested `add_trailer` directives must append the
parent trailers.

### 2. Duplicate important headers

Manually include all parent headers in nested locations:

```nginx
location /new-headers {
    add_header X-Frame-Options "DENY" always;  # Duplicated
    add_header Cache-Control "no-cache" always;
    return 200 "new-headers";
}
```

### 3. Set all headers at one level

Set all headers in the `server` section and avoid `add_header` in locations.

### 4. Use ngx_headers_more module

Use [ngx_headers_more](https://nginx-extras.getpagespeed.com/modules/headers-more/) module which has better inheritance behavior.

--8<-- "en/snippets/nginx-extras-cta.md"

## CLI and config options

- `--add-header-redefinition-headers headers` (Default: unset): Comma-separated, case-insensitive allowlist of headers to report when dropped. When unset, all dropped parent headers are reported. Example: `--add-header-redefinition-headers x-frame-options,content-security-policy`.

Config file example:
```
[add_header_redefinition]
headers = x-frame-options, content-security-policy
```

## Technical Details

### How Value-Aware Classification Works

Instead of blindly classifying headers as "secure" or "not secure", the plugin analyzes the **actual header value** to determine security intent:

```
Parent: add_header Cache-Control "no-store";
Child:  add_header X-Custom "value";
Result: MEDIUM severity (Cache-Control: no-store is security-protective)

Parent: add_header Cache-Control "public, max-age=3600";
Child:  add_header Cache-Control "no-store";
Result: No issue (child overrides with stricter policy)
```

This approach eliminates false positives for performance-only headers while still catching real security regressions.
