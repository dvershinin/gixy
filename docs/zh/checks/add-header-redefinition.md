---
title: "add_header 重定义陷阱"
description: "说明 add_header 的继承与重定义规则，避免在子级添加头时覆盖父级安全头（如 CSP、X-Frame-Options）。文章给出正确继承示例和排查要点，防止安全头丢失。适用于安全审计与上线前自检，帮助团队统一配置规范、减少误配并降低风险。"
---

# 通过 `add_header` 重定义响应头

_Gixy Check ID: `add_header_redefinition`_


很多人不了解指令继承机制，这常导致在嵌套级别试图新增响应头时误用 `add_header`。
Nginx 文档对此有说明（见 [docs](https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header)）：
> 可以存在多个 `add_header` 指令。仅当当前级别未定义任何 `add_header` 指令时，才会继承上一级别的这些指令。

逻辑很简单：如果你在某一层（例如 `server` 段）设置了响应头，而在下一级（例如 `location`）又设置了其他响应头，那么前者会被丢弃。

很容易验证：
- 配置：
```nginx
server {
  listen 80;
  add_header X-Frame-Options "DENY" always;
  location / {
      return 200 "index";
  }

  location /new-headers {
    # 特殊缓存控制
    add_header Cache-Control "no-cache, no-store, max-age=0, must-revalidate" always;
    add_header Pragma "no-cache" always;

    return 200 "new-headers";
  }
}
```
- 访问 `/`（响应中包含 `X-Frame-Options`）：
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
- 访问 `/new-headers`（出现了 `Cache-Control` 与 `Pragma`，但没有 `X-Frame-Options`）：
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

## 如何规避？
可以采用以下方法解决：
- 在 nginx 1.29.3 及更高版本的嵌套上下文中使用 `add_header_inherit merge;`；
- 重复设置重要响应头；
- 将所有响应头放在同一层设置（`server` 段通常是个好选择）；
- 使用 [ngx_headers_more](https://nginx-extras.getpagespeed.com/modules/headers-more/) 模块。

只有 `merge` 会把父级响应头追加到当前级。`on` 是默认值，当前级存在自己的
`add_header` 时仍不会继承父级响应头；`off` 则完全关闭继承。响应尾字段遵循相同
规则，应使用 `add_trailer_inherit merge;`。

--8<-- "zh/snippets/nginx-extras-cta.md"

### 命令行与配置选项

- `--add-header-redefinition-headers headers`（默认：未设置）：以逗号分隔的响应头白名单（不区分大小写）。设置后，仅当这些头在子级被“丢弃”时才会报告；未设置则报告所有被丢弃的头。示例：`--add-header-redefinition-headers x-frame-options,content-security-policy`。

配置示例：
```
[add_header_redefinition]
headers = x-frame-options, content-security-policy
```
