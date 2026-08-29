---
title: "Статическое разрешение DNS в proxy_pass"
description: "Имена хостов в proxy_pass разрешаются один раз при запуске — настройте resolver/resolve, чтобы динамические бэкенды продолжали работать."
---

# Статическое разрешение DNS в proxy_pass

_Идентификатор проверки Gixy: `missing_resolver`_


Обнаруживает конфигурации `proxy_pass` (и связанных директив), где имена хостов разрешаются только при запуске nginx, что потенциально приводит к отправке запросов на устаревшие IP-адреса.

## Почему это важно

Когда вы используете имя хоста напрямую в `proxy_pass`:

```nginx
proxy_pass https://api.example.com;
```

Nginx разрешает DNS **один раз при запуске** и кэширует этот IP навсегда. Если IP изменится (что часто происходит с облачными балансировщиками нагрузки, CDN или при отказоустойчивости), nginx продолжит отправлять трафик на старый IP до перезапуска.

Это может вызвать:
- **Сбои в работе сервиса** при изменении IP-адресов бэкенда
- **Проблемы безопасности**, если старые IP переназначены злоумышленникам
- **Сбои балансировки нагрузки** при использовании DNS-балансировки

## Умное обнаружение: Инверсная логика

Этот плагин использует **инверсную логику** для максимального охвата и безопасности:

> Вместо попытки идентифицировать публичные домены (невозможно без [Public Suffix List](https://publicsuffix.org/)), мы определяем, что **ТОЧНО ВНУТРЕННЕЕ**, и отмечаем **ВСЁ ОСТАЛЬНОЕ**.

Этот подход лучше, потому что:
- ✅ **Нет внешних зависимостей** — не нужен PSL, tldextract или любая библиотека
- ✅ **Нет жёстко закодированного списка TLD**, который устаревает
- ✅ **Новые TLD автоматически отмечаются** — `.ai`, `.xyz`, `.whatever` — все попадут в отчёт
- ✅ **Более безопасно** — ложные срабатывания лучше пропусков для инструментов безопасности
- ✅ **Защита от будущего** — работает с любым доменом, который когда-либо будет существовать

### 🔥 Обнаружение облачных провайдеров (ВЫСОКАЯ серьёзность)
Автоматически обнаруживает 50+ паттернов облачных провайдеров, где IP часто меняются:
- **AWS**: ELB, CloudFront, API Gateway, Elastic Beanstalk, Lambda URLs, S3, Amplify, Global Accelerator
- **Google Cloud**: Cloud Run, Cloud Functions, App Engine, Firebase, Google APIs
- **Azure**: App Service, API Management, CDN, Traffic Manager, Front Door, Static Web Apps
- **Cloudflare**: Workers, Pages, R2
- **CDN**: Akamai, Fastly, CDN77, StackPath, KeyCDN, BunnyCDN
- **PaaS**: Heroku, Vercel, Netlify, Railway, Render, Fly.io, Deno Deploy, Supabase, Neon, PlanetScale
- **Cloud**: DigitalOcean, Linode, Vultr, Scaleway, Hetzner, UpCloud

### 🐳 Учёт контейнерной оркестрации
Автоматически пропускает внутренние паттерны обнаружения сервисов:
- **Kubernetes**: `.svc.cluster.local`, `.pod.cluster.local`, `.default.svc`
- **Docker**: `.docker.internal`, `.docker.localhost`
- **Consul**: `.service.consul`, `.node.consul`, `.query.consul`
- **HashiCorp**: `.vault`, `.nomad`
- **Mesos/Marathon**: `.marathon.mesos`, `.dcos`
- **Rancher**: `.rancher.internal`
- **AWS Internal**: `.ec2.internal`, `.compute.internal`
- **OpenStack**: `.novalocal`, `.openstacklocal`

### 🎯 Обнаружение зарезервированных TLD согласно RFC
Распознаёт зарезервированные TLD согласно RFC 2606/6761/6762/7686:
- `.test`, `.example`, `.invalid` (RFC 2606)
- `.localhost` (RFC 6761)
- `.local` (RFC 6762 — mDNS/Bonjour)
- `.onion` (RFC 7686 — Tor)

### 🔍 Проверка директивы Resolver
Обнаруживает, когда вы используете переменную, но забыли настроить директиву `resolver`:

```nginx
# Это НЕ будет переразрешать без директивы resolver!
set $backend api.example.com;
proxy_pass http://$backend;  # ← Плагин предупредит об отсутствующем resolver
```

### 📦 Анализ Upstream
Проверяет блоки upstream на наличие серверов без параметра `resolve`:

```nginx
upstream backend {
    server api.example.com;  # ← Нет 'resolve' = статический DNS
}
```

## Что вызывает эту проверку

| Паттерн | Серьёзность | Пример |
|---------|----------|---------|
| Конечные точки облачных провайдеров | **ВЫСОКАЯ** | `proxy_pass https://my-app.herokuapp.com;` |
| Имена хостов публичных доменов | СРЕДНЯЯ | `proxy_pass https://api.example.com;` |
| Переменная без resolver | СРЕДНЯЯ | `set $x host.com; proxy_pass http://$x;` |
| Upstream без resolve | СРЕДНЯЯ | `upstream { server host.com; }` |

## Что не вызывает (избегаемые ложные срабатывания)

- ✅ IP-адреса (разрешение DNS не требуется)
- ✅ Unix-сокеты (`unix:/path/to/socket`)
- ✅ Внутренние домены (`.internal`, `.local`, `.lan`, `.corp`, `.home` и т.д.)
- ✅ Однокомпонентные имена хостов (`proxy_pass http://backend;`)
- ✅ Сервисы Kubernetes (`.svc.cluster.local`)
- ✅ Сервисы Consul (`.service.consul`)
- ✅ Docker internal (`.docker.internal`)
- ✅ URL с переменными И настроенным resolver
- ✅ Серверы upstream с параметром `resolve`

## Примеры

### Плохо: Конечная точка облачного провайдера (ВЫСОКАЯ серьёзность)

```nginx
# КРИТИЧНО: IP AWS ELB постоянно меняются!
location /api {
    proxy_pass https://my-app-123456789.us-east-1.elb.amazonaws.com;
}
```

### Плохо: Статическое имя хоста (СРЕДНЯЯ серьёзность)

```nginx
# DNS разрешается один раз при запуске
location /api {
    proxy_pass https://api.example.com;
}
```

### Плохо: Переменная без resolver

```nginx
# Переменная сама по себе не включает переразрешение!
set $backend api.example.com;
proxy_pass http://$backend;
```

### Плохо: Upstream без resolve

```nginx
upstream backend {
    server api.example.com:8080;  # Нет параметра resolve
}

server {
    location / {
        proxy_pass http://backend;
    }
}
```

### Хорошо: Переменная с resolver

```nginx
resolver 127.0.0.1 valid=30s;

server {
    location /api {
        set $backend api.example.com;
        proxy_pass https://$backend;
    }
}
```

### Хорошо: Upstream с resolve (nginx 1.27.3+)

```nginx
resolver 127.0.0.1;

upstream backend {
    server api.example.com:8080 resolve;
}

server {
    location / {
        proxy_pass http://backend;
    }
}
```

### Хорошо: Внутренний сервис (автоматически пропускается)

```nginx
# Сервис Kubernetes — плагин знает, что это внутренний
proxy_pass http://api-service.default.svc.cluster.local;
```

## Проверяемые директивы

Этот плагин анализирует все директивы, связанные с проксированием:
- `proxy_pass`
- `fastcgi_pass`
- `uwsgi_pass`
- `scgi_pass`
- `grpc_pass`

## Конфигурация

Отключите этот плагин в `.gixy.yml`:

```yaml
plugins:
  missing_resolver: false
```

## Ссылки

- [Директива resolver в nginx](https://nginx.org/ru/docs/http/ngx_http_core_module.html#resolver)
- [Параметр resolve сервера upstream в nginx](https://nginx.org/ru/docs/http/ngx_http_upstream_module.html#server)
- [Блог NGINX: DNS Service Discovery](https://www.nginx.com/blog/dns-service-discovery-nginx-plus/)
