---
title: "配置与使用指南"
description: "配置 Gixy：调优检查项、CLI 参数和变量扩展，让 NGINX 安全扫描更精准。支持配置文件、命令行参数和环境变量等多种配置方式。"
---

### 配置（gixy.cfg）

Gixy 会按以下顺序读取配置（先找到先用）：

- `/etc/gixy/gixy.cfg`
- `~/.config/gixy/gixy.conf`

也可以通过 `-c/--config` 指定自定义配置路径，并使用 `--write-config` 输出带注释的示例配置。

配置文件使用简单的 `key = value` 键值对，可选的分段，以及支持使用 `[a, b, c]` 语法的列表。键名与长 CLI 选项一致，均使用连字符，例如 `--disable-includes` 对应 `disable-includes`。

注意：严重级别过滤仅限 CLI 通过重复 `-l`（如 `-l`、`-ll`、`-lll`），配置文件不读取该项。

### 管理插件

- 仅运行指定插件：将 `tests` 设置为以逗号分隔的插件类名列表。
- 跳过指定插件：将 `skips` 设置为以逗号分隔的插件类名列表。

示例：

```ini
# 仅运行这些插件
tests = if_is_evil, http_splitting

# 排除这些插件
skips = origins, version_disclosure
```

### 插件专用选项

插件选项可以按“段名为插件类名（下划线改为连字符）”的方式提供。段内键也使用连字符。例如：

```ini
[origins]
domains = example.com, example.org
https-only = true

[regex-redos]
deep = true
```

不使用段也可以实现相同效果：把插件名与选项以连字符拼接，例如 `origins-domains = ...`，但分段写法更易组织。

### 其他常用选项

- 输出格式：`format = console|text|json|checkstyle`（等同 `-f/--format`）
- 写报告到文件：`output = /path/to/report.txt`（等同 `-o/--output`）
- 禁用 include 处理：`disable-includes = true`（等同 `--disable-includes`）
- 自定义变量目录：`vars-dirs = [/etc/gixy/vars, ~/.config/gixy/vars]`（详见“自定义变量扩展”）
- 深度分析：`deep = true`（等同 `--deep`；启用本地 ReDoctor 自动机分析和受限的自定义 VM 模糊测试）

### 完整示例

```ini
# gixy.cfg

format = console
output = /tmp/gixy-report.txt
disable-includes = false

# 限制仅分析部分插件
tests = if_is_evil, http_splitting

# 跳过某些插件
skips = version_disclosure

# 载入自定义变量定义（见 variables-dropins）
vars-dirs = [/etc/gixy/vars, ~/.config/gixy/vars]

[origins]
domains = example.com, example.org
https-only = true

[regex-redos]
deep = true
```
