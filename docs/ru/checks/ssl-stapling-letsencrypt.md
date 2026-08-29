---
title: "OCSP stapling с сертификатом Let's Encrypt"
description: "Let's Encrypt отключил свои OCSP-респондеры 2025-08-06, поэтому ssl_stapling on с сертификатом certbot ничего не сшивает и является мёртвой конфигурацией."
---

# OCSP stapling с сертификатом Let's Encrypt

_Идентификатор проверки Gixy: `ssl_stapling_letsencrypt`_

Почти каждое руководство по TLS для nginx, написанное до 2025 года,
заканчивается одними и теми же тремя строками:

```nginx
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;
```

Для сертификата Let's Encrypt эти строки теперь не делают ровным счётом ничего.

## Что изменилось

Let's Encrypt объявил об отказе от OCSP в июле 2024 года и выполнил его в
несколько этапов:

- **Начало 2025 года** — новые сертификаты перестали содержать URL
  OCSP-респондера в расширении Authority Information Access.
- **2025-08-06** — OCSP-респондеры были полностью выключены.

OCSP stapling работает так: nginx читает URL респондера из сертификата и
запрашивает у центра сертификации подписанный статус. Если URL в сертификате
нет, запрашивать нечего, поэтому `ssl_stapling on` навсегда остаётся
бездействующим. Отзыв сертификатов Let's Encrypt обеспечивается коротким сроком
их жизни и CRL, которые браузеры получают через агрегаторы (CRLite, CRLSets),
а не запросами клиентов к респондеру.

Это мёртвая конфигурация, а не уязвимость — отсюда и низкая критичность. Убрать
её всё же стоит: она создаёт шум в логах при запуске, переезжает в каждую копию
конфигурации, снятую с сервера, и вводит следующего читателя в заблуждение,
будто проверка отзыва действительно выполняется.

## Плохой пример

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate         /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key     /etc/letsencrypt/live/example.com/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;

    resolver 127.0.0.1 valid=300s;

    ssl_stapling on;         # сшивать нечего
    ssl_stapling_verify on;
}
```

## Хороший пример

Уберите блок stapling для хостов на Let's Encrypt:

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
}
```

Сохраните stapling там, где он всё ещё приносит пользу — у коммерческого центра
сертификации, который поддерживает OCSP-респондер:

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

О требовании к резолверу, которое действует всегда, когда stapling реально
используется, см. [OCSP stapling без резолвера](ssl-stapling-without-resolver.md).

## Что эта проверка не помечает

- `ssl_stapling off;` или сервер, который переопределяет `on`, заданный на
  уровне `http`.
- Сертификаты вне `/etc/letsencrypt/` — включая другие ACME-клиенты, чей центр
  сертификации ещё поддерживает OCSP.
- Серверы без SSL.

## Ложные срабатывания

Проверка опирается на путь certbot `/etc/letsencrypt/`. Сертификат не от Let's
Encrypt, лежащий в этом каталоге, — случай необычный, но возможный, поэтому
формулировка находки содержит «по-видимому», а критичность низкая. Проверить
можно так:

```console
$ openssl x509 -in /etc/letsencrypt/live/example.com/cert.pem -noout -ocsp_uri
```

Пустой вывод означает, что сшивать статус не у кого, независимо от центра
сертификации.
