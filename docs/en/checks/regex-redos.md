---
title: "Regular Expression Denial of Service (ReDoS)"
description: "Find regex ReDoS patterns in NGINX—stop catastrophic backtracking by reshaping nested quantifiers and overlaps."
---

# Regular Expression Denial of Service (ReDoS)

_Gixy Check ID: `regex_redos`_


ReDoS (Regular Expression Denial of Service) occurs when a regex pattern with certain structures causes catastrophic backtracking on specially crafted input, consuming excessive CPU time.

## Why this matters

nginx uses PCRE regular expressions in several directives where user-controlled input is matched:

- `location ~ pattern` - matches request URI
- `if ($var ~ pattern)` - matches variables like `$http_referer`, `$request_uri`
- `rewrite pattern replacement` - matches request URI
- `server_name ~pattern` - matches Host header

An attacker who can craft input matching a vulnerable regex can cause nginx workers to hang, leading to denial of service with minimal attack resources.

## Vulnerable patterns detected

### 1. Nested quantifiers (exponential backtracking)

When a quantifier (`+`, `*`, `{n,m}`) is applied to a group that itself contains a quantifier:

```nginx
# BAD - (a+)+ causes exponential backtracking
location ~ ^/(a+)+$ {
    return 200;
}

# BAD - nested groups with quantifiers
location ~ ^/((ab)+)+/files$ {
    return 200;
}

# BAD - star inside plus
location ~ ^/(a*)+/path$ {
    return 200;
}
```

Attack input: `/aaaaaaaaaaaaaaaaaaaaaaaaaab` can cause the regex engine to try exponentially many paths before failing.

### 2. Overlapping alternatives with quantifiers (polynomial backtracking)

When alternatives in a group can match overlapping input and the group is quantified:

```nginx
# BAD - 'a' is a prefix of 'ab'
location ~ ^/(a|ab)+$ {
    return 200;
}

# BAD - '.' matches everything including 'x'
location ~ ^/(.|x)+/path$ {
    return 200;
}
```

## Safe patterns

```nginx
# GOOD - simple character class
location ~ ^/[a-z]+$ {
    return 200;
}

# GOOD - bounded quantifier
location ~ ^/\d{1,10}$ {
    return 200;
}

# GOOD - non-overlapping alternatives
location ~ ^/(foo|bar)$ {
    return 200;
}

# GOOD - single quantifier on simple pattern
location ~ ^/api/v[0-9]+/users$ {
    return 200;
}
```

## How gixy detects ReDoS

Gixy analyzes the parsed regex structure locally, without sending patterns to an external service and without executing attacker-controlled regexes. The default fast analysis detects:

1. **Nested quantifiers** - any pattern where a variable-length quantifier contains another variable-length quantifier
2. **Overlapping alternatives** - alternation groups inside quantifiers where branches can match the same input

For a more complete analysis, run:

```bash
gixy --deep /etc/nginx/nginx.conf
```

Deep mode uses a recheck-inspired position automaton. It looks for EDA structures (two distinct cycles that consume the same input) and IDA chains (multiple quantified regions that can consume the same input), then classifies findings as exponential or polynomial with a degree. This catches non-local cases such as `.*a.*a` that simple nested-quantifier checks miss, and clears local false positives such as `(a|ab)+` when the automaton proves the paths unambiguous.

Lookarounds and other constructs that cannot be represented safely fall back to the default structural checks. Both modes are static: Gixy never calls `re.match`, `re.search`, or another backtracking matcher with the nginx pattern.

## Recommendations

1. **Avoid nested quantifiers** - restructure patterns to use single-level quantifiers
2. **Use non-overlapping alternatives** - ensure alternatives don't share common prefixes
3. **Use bounded quantifiers** - `{1,100}` instead of `+` or `*` where possible
4. **Prefer prefix/exact locations** - use `location /path` or `location = /path` instead of regex when possible
5. **Run deep analysis before deploying** - use `gixy --deep nginx.conf` to check the complete configuration locally

## References

- [OWASP: Regular expression Denial of Service](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [Wikipedia: ReDoS](https://en.wikipedia.org/wiki/ReDoS)
- [Cloudflare: Details of the Cloudflare outage on July 2, 2019](https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/) - a famous ReDoS incident

--8<-- "en/snippets/nginx-extras-cta.md"
