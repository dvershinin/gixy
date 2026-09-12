---
title: "Gixy: анализ конфигурации NGINX"
description: "Открытый анализатор конфигураций NGINX: находит уязвимости, пропуски в hardening и проблемные настройки производительности до выката."
---

GIXY
====
[![Mozilla Public License 2.0](https://img.shields.io/badge/license-MPLv2.0-brightgreen?style=flat-square)](https://github.com/dvershinin/gixy/blob/master/LICENSE)
[![Python tests](https://github.com/dvershinin/gixy/actions/workflows/pythonpackage.yml/badge.svg)](https://github.com/dvershinin/gixy/actions/workflows/pythonpackage.yml)
[![Your feedback is greatly appreciated](https://img.shields.io/maintenance/yes/2025.svg?style=flat-square)](https://github.com/dvershinin/gixy/issues/new)
[![GitHub issues](https://img.shields.io/github/issues/dvershinin/gixy.svg?style=flat-square)](https://github.com/dvershinin/gixy/issues)
[![GitHub pull requests](https://img.shields.io/github/issues-pr/dvershinin/gixy.svg?style=flat-square)](https://github.com/dvershinin/gixy/pulls)

# Обзор
<img style="float: right;" width="192" height="192" src="../gixy.png" alt="Логотип Gixy">

Gixy — это инструмент для анализа конфигурации Nginx.
Его цель — предотвращать ошибки конфигурации безопасности и автоматизировать выявление проблем.

В настоящее время поддерживаются Python 3.6–3.13.

Дисклеймер: Gixy хорошо протестирован на GNU/Linux; на других ОС возможны нюансы.

!!! tip "Укрепляйте NGINX с поддерживаемыми RPM"
    Используйте NGINX Extras от GetPageSpeed для постоянно обновляемого NGINX и модулей на RHEL/CentOS/Alma/Rocky.
    [Подробнее](https://nginx-extras.getpagespeed.com/).

# Что умеет
Сейчас Gixy выявляет:

*   [Подделка серверных запросов (SSRF)](checks/ssrf.md)
*   [HTTP‑разделение](checks/http-splitting.md)
*   [Проблемы проверки Referer/Origin](checks/origins.md)
*   [Переопределение заголовков через "add_header"](checks/add-header-redefinition.md)
*   [Подделка заголовка Host](checks/host-spoofing.md)
*   [none в valid_referers](checks/valid-referers.md)
*   [Многострочные заголовки ответа](checks/add-header-multiline.md)
*   [Траверс путей из‑за неправильного alias](checks/alias-traversal.md)
*   [if опасен в контексте location](checks/if-is-evil.md)
*   [allow без deny](checks/allow-without-deny.md)
*   [Установка Content‑Type через add_header](checks/add-header-content-type.md)
*   [Использование внешних DNS‑резолверов](checks/resolver-external.md)
*   [Раскрытие версии](checks/version-disclosure.md)
*   [Нормализация/декодирование пути при proxy_pass](checks/proxy-pass-normalized.md)
*   [Регэксп может вызвать ReDoS](checks/regex-redos.md)

## Производительность

*   [try_files без open_file_cache](checks/try-files-is-evil-too.md)
*   [worker_connections и лимит дескрипторов](checks/worker-rlimit-nofile-vs-connections.md)
*   [Низкое значение keepalive_requests](checks/low-keepalive-requests.md)

См. также задачи с меткой ["new plugin"](https://github.com/dvershinin/gixy/issues?q=is%3Aissue+is%3Aopen+label%3A%22new+plugin%22).

# Установка

## CentOS/RHEL и другие RPM‑системы

```bash
yum -y install https://extras.getpagespeed.com/release-latest.rpm
yum -y install gixy

# Необязательно: добавить глубокий анализ ReDoS через ReDoctor
yum -y install gixy-deep
```

Базовый RPM включает быстрый встроенный анализ ReDoS и не зависит от ReDoctor.
Подписанный RPM [`gixy-deep`](https://extras.getpagespeed.com/redhat/repoview/gixy-deep.html)
добавляет ReDoctor для `gixy --deep`, не меняя зависимости базового пакета.

## macOS / Linux (Homebrew)

```bash
brew install gixy
```

Готовые бинарные пакеты (bottles) собраны для macOS (Apple Silicon и Intel) и
Linux (`x86_64`, `arm64`).

## Alpine Linux

```bash
apk add gixy
```

Пакет называется `gixy` и находится в репозитории `community`. Сейчас доступен
в ветке **edge**: он попал в aports уже после ответвления `v3.24`, поэтому в
стабильные выпуски войдёт со следующим релизом Alpine. На стабильной версии до
тех пор используйте установку с PyPI (ниже).

## Arch Linux (AUR)

```bash
yay -S gixy-ng
```

Публикуется как `gixy-ng` (устаревший слот `gixy` в AUR занят другим
сопровождающим и застрял на выпуске 0.1.20); пакет объявляет `provides=('gixy')`
и `conflicts=('gixy')`, поэтому является полноценной заменой. Подойдёт любой
AUR-хелпер (`paru`, `yay`, либо `makepkg -si` вручную).

## Conda (conda-forge)

```bash
conda install -c conda-forge gixy-ng
```

Работает также с `mamba` и `micromamba`. Пакет называется `gixy-ng`, но
исполняемый файл по-прежнему `gixy`. Пакет собран как `noarch`, поэтому одна и та
же сборка подходит для Linux, macOS и Windows.

## Другие системы

Gixy публикуется на [PyPI](https://pypi.python.org/pypi/gixy-ng). Рекомендуемый способ установки — через pip:

```bash
pip install gixy-ng
```

Для необязательного глубокого анализа ReDoS через ReDoctor установите:

```bash
pip install 'gixy-ng[deep]'
```

Запустите Gixy и посмотрите результат:
```bash
gixy
```

# Использование
По умолчанию Gixy анализирует конфигурацию Nginx по пути `/etc/nginx/nginx.conf`.

Можно указать нужный путь:
```
$ gixy /etc/nginx/nginx.conf

==================== Results ===================

Problem: [http_splitting] Possible HTTP-Splitting vulnerability.
Description: Using variables that can contain "\n" may lead to http injection.
Additional info: https://github.com/dvershinin/gixy/blob/master/docs/ru/checks/http-splitting.md
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

Или пропустить часть проверок:
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

Другие аргументы смотрите в справке: `gixy --help`

Можно передать конфигурацию через stdin, например:

```bash
echo "resolver 1.1.1.1;" | gixy -
```

## Использование Docker
Образ доступен на Docker Hub: [getpagespeed/gixy](https://hub.docker.com/r/getpagespeed/gixy/).
Смонтируйте конфиг как том и передайте путь к нему при запуске контейнера:
```
$ docker run --rm -v `pwd`/nginx.conf:/etc/nginx/conf/nginx.conf getpagespeed/gixy /etc/nginx/conf/nginx.conf
```

Если у вас уже есть образ с конфигурацией Nginx, можно примонтировать её во второй контейнер:
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

# Вклад
Мы всегда рады вашему участию! Вы можете:
  * Открыть issue с предложениями и описанием проблем;
  * Сделать форк и отправить pull request;
  * Улучшить документацию.

Требования к коду:
  * Соблюдайте [pep8](https://www.python.org/dev/peps/pep-0008/) по возможности;
  * Pull‑request с новыми плагинами должен содержать юнит‑тесты.
