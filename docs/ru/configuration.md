---
title: "Руководство по настройке"
description: "Настройте Gixy под свой процесс: плагины, CLI-флаги и drop-in переменные для точных проверок NGINX."
---

### Конфигурация (gixy.cfg)

Gixy читает конфигурацию из следующих путей (первый найденный побеждает):

- `/etc/gixy/gixy.cfg`
- `~/.config/gixy/gixy.conf`

Также можно указать свой путь через `-c/--config` и сгенерировать шаблон с подсказками через `--write-config`.

Файл конфигурации использует пары `key = value`, необязательные секции и поддерживает списки в виде `[a, b, c]`. Имена ключей совпадают с длинными флагами CLI и используют дефисы, например `--disable-includes` → `disable-includes`.

Примечание: фильтр серьёзности доступен только через CLI с помощью повторов `-l` (например, `-l`, `-ll`, `-lll`). Из файла конфигурации он не читается.

### Управление плагинами

- Запустить только выбранные плагины: укажите `tests` со списком имён классов плагинов через запятую.
- Пропустить конкретные плагины: укажите `skips` со списком имён классов плагинов через запятую.

Примеры:

```ini
# Запускать только эти плагины
tests = if_is_evil, http_splitting

# Эти плагины исключить
skips = origins, version_disclosure
```

### Параметры плагинов

Опции плагинов можно указывать в секциях, где имя секции — это имя класса плагина с дефисами вместо подчёркиваний. Ключи в секциях также используют дефисы. Примеры:

```ini
[origins]
domains = example.com, example.org
https-only = true

[regex-redos]
deep = true
```

Того же эффекта можно добиться без секций, объединив имя плагина и опцию через дефис, например `origins-domains = ...`, но секции удобнее.

### Другие полезные параметры

- Формат вывода: `format = console|text|json|checkstyle` (то же, что `-f/--format`)
- Запись отчёта в файл: `output = /path/to/report.txt` (то же, что `-o/--output`)
- Отключить обработку include: `disable-includes = true` (то же, что `--disable-includes`)
- Каталоги кастомных переменных: `vars-dirs = [/etc/gixy/vars, ~/.config/gixy/vars]` (см. «Пользовательские переменные (drop-ins)»)
- Глубокий анализ: `deep = true` (то же, что `--deep`; требует `gixy-ng[deep]` из pip или RPM `gixy-deep` и включает локальный анализ ReDoctor с автоматами и ограниченным фаззингом в собственной VM)

### Полный пример

```ini
# gixy.cfg

format = console
output = /tmp/gixy-report.txt
disable-includes = false

# Ограничить анализ подмножеством плагинов
tests = if_is_evil, http_splitting

# Пропустить некоторые плагины
skips = version_disclosure

# Загрузить определения переменных (см. variables-dropins)
vars-dirs = [/etc/gixy/vars, ~/.config/gixy/vars]

[origins]
domains = example.com, example.org
https-only = true

[regex-redos]
deep = true
```
