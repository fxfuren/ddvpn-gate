# DDVPN Gate — Copilot Instructions

## 📌 Архитектура и назначение проекта

`ddvpn-gate` — микросервис авторизации на Go для защиты страниц и ссылок на подписки в системе Remnawave.
Сервис работает в связке с Nginx через модуль `ngx_http_auth_request_module`.

### Основные эндпоинты:
- `GET /health` — healthcheck микросервиса.
- `GET /auth` — проверка доступа для внешнего сквада (`ALLOWED_SQUAD_ID`), тегов обхода (`BYPASS_TAG`, `BYPASS_PC_TAG`) и валидация клиентских заголовков (`Accept`, `User-Agent`, `X-Device-OS`).
- `GET /auth-default` — проверка доступа для дефолтного внутреннего сквада (`DEFAULT_SQUAD_ID`) и тегов обхода (`BYPASS_TAG`), без фильтрации по клиенту.

---

## ⚠️ Инварианты Nginx `auth_request`

1. **Семантика статус-кодов**:
   - `2xx` — доступ разрешен, Nginx проксирует оригинальный запрос на backend.
   - `401` — пользователь не найден в Remnawave (`client.ErrUserNotFound`, `user_not_found`). Nginx перехватывает этот статус директивой `error_page 401 =404 /error/404.html;`, подменяет HTTP-код на 404 и отдает страницу ошибки напрямую, не обращаясь к бэкенду подписок (который намеренно сбрасывает TCP-сокет через `res.socket?.destroy()`, вызывая 502/500).
   - `403` — доступ запрещен (не совпадает squad, отсутствует bypass-тег). Nginx отдает клиенту 403 (`error_page 403 /error/403.html;`).
   - **Любой другой код (включая прямой 404 и 5xx)** — модуль Nginx `auth_request` считает сбоем авторизатора и немедленно возвращает клиенту `500 Internal Server Error`. Прямой 404 из `ddvpn-gate` возвращать **нельзя**.
2. **Fail-Open при сбое Remnawave**:
   - При сетевых сбоях или 5xx ошибках от Remnawave (`client.ErrPanelUnavailable`) срабатывает `panelState.MarkUnavailable()`.
   - В этом состоянии сервис возвращает `HTTP 200 OK` (`panel_unavailable_fallback` / `panel_unavailable_bypass`), предотвращая отказ в обслуживании пользователей при временной недоступности панели.
3. **Конфигурация Nginx subrequest**:
   - Директива `internal;` обязательна для location `/_auth_check`.
   - `proxy_pass_request_body off;` и `proxy_set_header Content-Length "";` предотвращают зависание буфера при POST/PUT запросах.
   - Обязательна передача `proxy_set_header X-Original-URI $request_uri;`.

---

## 🛡️ Применимые практики безопасности (Security Skills)

- **API Gateway Security Controls** (`implementing-api-gateway-security-controls`):
  - Очистка входящих заголовков в Nginx перед проксированием.
  - Изоляция внутренних auth-эндпоинтов от прямого внешнего доступа через `internal;`.
- **Защита от перебора и подбора идентификаторов (BOLA/IDOR)** (`testing-api-security-with-owasp-top-10`):
  - Проверка валидности `shortUuid` перед обращением к бэкенду.
  - Passthrough для 404 не раскрывает данных пользователя и отдает пустую страницу панели.
- **Ограничение частоты запросов** (`implementing-api-abuse-detection-with-rate-limiting`):
  - Применение rate limiting на уровне Nginx (`limit_req_zone`) для эндпоинтов авторизации.
- **Харденинг контейнеров** (`hardening-docker-containers-for-production`):
  - Запуск микросервиса от непривилегированного пользователя в Dockerfile (`USER nonroot:nonroot`).
  - Минимизация слоев и использование scratch/distroless/alpine баз.
  - Периодическое сканирование образов через Trivy (`scanning-docker-images-with-trivy`).

---

## 💻 Соглашения по разработке на Go

- **Обработка ошибок**: Использовать типизированные sentinel-ошибки (`client.ErrUserNotFound`, `client.ErrPanelUnavailable`), оборачивать через `fmt.Errorf("%w: ...", err)` и проверять через `errors.Is(err, ...)`.
- **Потокобезопасность**: Доступ к разделяемому состоянию (`PanelState`) защищать через `sync.RWMutex`.
- **Логирование**: Использовать `logrus`. Ошибки 404 (not found) логировать на уровне `Info`, чтобы не засорять логи ошибок при валидных обращениях к несуществующим ресурсам или статике.
- **Тестирование**: Все изменения логики в `client`, `service` и `handler` должны сопровождаться параллельными тестами (`t.Parallel()`) с использованием `httptest.NewServer` и `httptest.NewRecorder`.
