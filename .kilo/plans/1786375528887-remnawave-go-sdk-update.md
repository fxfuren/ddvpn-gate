# Анализ совместимости с Remnawave API 3.x

## Источник истины

Проверено по OpenAPI spec `api-1 (6).json` — актуальная схема панели 3.x.

---

## Вывод: обновлений не требуется

### `GET /api/users/by-short-uuid/{shortUuid}`

Схема `UserResponseDto` в API 3.x (строки 16170–16372 spec):

```json
{
  "response": {
    "id": 42,
    "shortUuid": "6_mX7yVYAHAej2qM",
    "username": "alice",
    "tag": "ADMIN",
    "externalSquadUuid": "uuid-or-null",
    "activeInternalSquads": [{"uuid": "...", "name": "..."}],
    "userTraffic": { ... },
    ...
  }
}
```

**Обёртка `response` сохранилась** (`"required": ["response"]` — строка 16369–16371 spec).

Поля, используемые проектом — не изменились:

| JSON-ключ | Тип в spec 3.x | Текущая Go-структура | Совместимость |
|-----------|---------------|----------------------|---------------|
| `username` | `string` | `string` | ✓ |
| `tag` | `string, nullable` | `*string` | ✓ |
| `externalSquadUuid` | `string (uuid), nullable` | `*string` | ✓ |
| `activeInternalSquads[].uuid` | `string (uuid)` | `string` | ✓ |
| `activeInternalSquads[].name` | `string` | `string` | ✓ |

Новые поля (`id`, `shortUuid`, `userTraffic`, `vlessUuid` и др.) — игнорируются `encoding/json` автоматически. Лишних полей в Go-структуре нет.

### `GET /api/system/health`

Маршрут не изменился. Обновлений не требует.

### Ошибки (404, 500)

API 3.x возвращает: `{ "timestamp": "...", "path": "...", "message": "...", "errorCode": "A025" }`.

Текущий `extractAPIError` читает поле `message` — совместимо. Поля `error` и `response.message`/`response.error` отсутствуют в новом формате, но их отсутствие не ломает логику (просто не заполняются).

---

## Затронутые файлы: нет

Код в `internal/client/remnawave.go` и тесты в `internal/client/remnawave_test.go` корректно работают с API 3.x **без изменений**.

---

## Что можно улучшить (опционально, не обязательно)

Если хочется привести `apiErrorResponse` в соответствие с актуальным форматом ошибок:

```go
// Текущий (избыточный, но рабочий):
type apiErrorResponse struct {
    Message  string `json:"message"`
    Error    string `json:"error"`
    Response struct {
        Message string `json:"message"`
        Error   string `json:"error"`
    } `json:"response"`
}

// Актуальный для API 3.x:
type apiErrorResponse struct {
    Message   string `json:"message"`
    ErrorCode string `json:"errorCode"`
}
```

Это **не влияет на поведение** — `message` читается в обоих случаях. Рефакторинг опциональный.

---

## Итог

Текущая реализация `internal/client/remnawave.go` **совместима с Remnawave API 3.x**. Никаких изменений в коде не требуется.

Если всё же что-то не работает с панелью — проблема не в формате JSON (он совместим), а в другом: токен авторизации, сетевая связность, версия панели vs. spec.
