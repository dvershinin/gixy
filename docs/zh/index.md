---
title: "Gixy：NGINX 安全与配置加固扫描器"
description: "开源 NGINX 配置分析器，在上线前找出安全隐患、加固缺口和性能陷阱。支持 SSRF、HTTP 拆分、主机头欺骗等多种漏洞检测。"
---

GIXY
====
[![Mozilla Public License 2.0](https://img.shields.io/badge/license-MPLv2.0-brightgreen?style=flat-square)](https://github.com/dvershinin/gixy/blob/master/LICENSE)
[![Python tests](https://github.com/dvershinin/gixy/actions/workflows/pythonpackage.yml/badge.svg)](https://github.com/dvershinin/gixy/actions/workflows/pythonpackage.yml)
[![Your feedback is greatly appreciated](https://img.shields.io/maintenance/yes/2025.svg?style=flat-square)](https://github.com/dvershinin/gixy/issues/new)
[![GitHub issues](https://img.shields.io/github/issues/dvershinin/gixy.svg?style=flat-square)](https://github.com/dvershinin/gixy/issues)
[![GitHub pull requests](https://img.shields.io/github/issues-pr/dvershinin/gixy.svg?style=flat-square)](https://github.com/dvershinin/gixy/pulls)

# 概览
<img style="float: right;" width="192" height="192" src="../gixy.png" alt="Gixy 标志">

Gixy 是一款用于分析 Nginx 配置的工具。
目标是预防安全性错误配置并自动化缺陷检测。

当前支持的 Python 版本为 3.6 至 3.13。

声明：Gixy 在 GNU/Linux 上经过充分测试；其他系统可能存在少量差异。

!!! tip "加固 NGINX，使用维护的 RPM"
    使用 GetPageSpeed 提供的 NGINX Extras 在 RHEL/CentOS/Alma/Rocky 上获取持续更新的 NGINX 与模块。
    [了解更多](https://nginx-extras.getpagespeed.com/).

# 功能
Gixy 目前可以发现：

*   [服务器端请求伪造 (SSRF)](checks/ssrf.md)
*   [HTTP 拆分](checks/http-splitting.md)
*   [引用来源（Referer/Origin）校验问题](checks/origins.md)
*   [通过 "add_header" 重定义响应头](checks/add-header-redefinition.md)
*   [伪造请求的 Host 头](checks/host-spoofing.md)
*   [在 valid_referers 中使用 none](checks/valid-referers.md)
*   [多行响应头](checks/add-header-multiline.md)
*   [错误 alias 导致路径穿越](checks/alias-traversal.md)
*   [在 location 中使用 if 存在风险](checks/if-is-evil.md)
*   [仅 allow 未配套 deny](checks/allow-without-deny.md)
*   [使用 add_header 设置 Content‑Type](checks/add-header-content-type.md)
*   [使用外部 DNS 解析器](checks/resolver-external.md)
*   [版本泄露](checks/version-disclosure.md)
*   [proxy_pass 归一化/解码路径风险](checks/proxy-pass-normalized.md)
*   [正则可能导致 ReDoS](checks/regex-redos.md)

更多即将支持的检测项，见 Issues 中的 ["new plugin"](https://github.com/dvershinin/gixy/issues?q=is%3Aissue+is%3Aopen+label%3A%22new+plugin%22)。

# 安装

## CentOS/RHEL 及其他 RPM 系统

```bash
yum -y install https://extras.getpagespeed.com/release-latest.rpm
yum -y install gixy

# 可选：添加由 ReDoctor 支持的深度 ReDoS 分析
yum -y install gixy-deep
```

基础 RPM 包含 Gixy 默认的快速 ReDoS 启发式检查，且不依赖 ReDoctor。
签名的 [`gixy-deep` RPM](https://extras.getpagespeed.com/redhat/repoview/gixy-deep.html)
会为 `gixy --deep` 添加 ReDoctor，同时保持基础包的依赖不变。

### 其他系统

Gixy 在 [PyPI](https://pypi.python.org/pypi/gixy-ng) 发布，建议使用 pip 安装：

```bash
pip install gixy-ng
```

如需可选的 ReDoctor 深度 ReDoS 分析，请安装：

```bash
pip install 'gixy-ng[deep]'
```

运行 Gixy 检查结果：
```bash
gixy
```

# 用法
默认分析 `/etc/nginx/nginx.conf`。

也可以指定路径：
```
$ gixy /etc/nginx/nginx.conf

==================== Results ===================

Problem: [http_splitting] Possible HTTP-Splitting vulnerability.
Description: Using variables that can contain "\n" may lead to http injection.
Additional info: https://github.com/dvershinin/gixy/blob/master/docs/zh/checks/http-splitting.md
Reason: At least variable "$action" can contain "\n"
Pseudo config:
include /etc/nginx/sites/default.conf;

	server {

		location ~ /v1/((?<action>[^.]*)\.json)?$ {
			add_header X-Action $action;
		}
	}


==================== Summary ===================
Total issues:
    Unspecified: 0
    Low: 0
    Medium: 0
    High: 1
```

跳过某些检查：
```
$ gixy --skips http_splitting /etc/nginx/nginx.conf

==================== Results ===================
No issues found.

==================== Summary ===================
Total issues:
    Unspecified: 0
    Low: 0
    Medium: 0
    High: 0
```

更多参数见帮助：`gixy --help`

也可通过 stdin 传入配置：

```bash
echo "resolver 1.1.1.1;" | gixy -
```

## Docker 用法
镜像托管在 Docker Hub：[getpagespeed/gixy](https://hub.docker.com/r/getpagespeed/gixy/)。
将需分析的配置以卷方式挂载并传入路径：
```
$ docker run --rm -v `pwd`/nginx.conf:/etc/nginx/conf/nginx.conf getpagespeed/gixy /etc/nginx/conf/nginx.conf
```

如果已有包含 Nginx 配置的镜像，也可将其作为卷挂载至 Gixy 容器：
```
$  docker run --rm --name nginx -d -v /etc/nginx nginx:alpine
f68f2833e986ae69c0a5375f9980dc7a70684a6c233a9535c2a837189f14e905

$  docker run --rm --volumes-from nginx dvershinin/gixy /etc/nginx/nginx.conf

==================== Results ===================
No issues found.

==================== Summary ===================
Total issues:
    Unspecified: 0
    Low: 0
    Medium: 0
    High: 0

```

# 参与贡献
欢迎贡献 Gixy！你可以：
  * 提交 Issue 提出改进与问题；
  * Fork 仓库并发起 Pull Request；
  * 改进文档。

代码规范：
  * 遵循 [pep8](https://www.python.org/dev/peps/pep-0008/)；
  * 新插件的 PR 必须包含单元测试。
