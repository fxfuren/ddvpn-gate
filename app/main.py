import logging
from typing import Annotated
from fastapi import FastAPI, Header, Response, status
from remnawave import RemnawaveSDK
from app.config import settings

# Настраиваем логирование
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("remnagate")

app = FastAPI(title="RemnaGate", version="1.0.5")

client = RemnawaveSDK(
    base_url=settings.remnawave_base_url,
    token=settings.remnawave_token
)

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.get("/auth")
async def verify_access(
    x_original_uri: Annotated[str | None, Header()] = None
):
    if not x_original_uri:
        return Response(status_code=status.HTTP_403_FORBIDDEN)

    try:
        # Парсим shortUuid из URL (берем последний сегмент)
        clean_path = x_original_uri.split('?')[0].rstrip('/')
        short_uuid = clean_path.split('/')[-1]
    except Exception:
        logger.error(f"Failed to parse URI: {x_original_uri}")
        return Response(status_code=status.HTTP_403_FORBIDDEN)

    # Простая валидация длины
    if len(short_uuid) < 8:
        return Response(status_code=status.HTTP_403_FORBIDDEN)

    try:
        # Запрашиваем пользователя
        user_response = await client.users.get_user_by_short_uuid(short_uuid)
        user = user_response.response if hasattr(user_response, 'response') else user_response
        
        username = getattr(user, 'username', 'Unknown')
        user_tag = getattr(user, 'tag', None)
        
        # 1. ПРОВЕРКА ADMIN (TAG)
        # Приводим к строке и удаляем пробелы для надежности
        if user_tag and str(user_tag).strip() == settings.bypass_tag.strip():
            logger.info(f"🔓 ACCESS GRANTED (Admin Tag): User '{username}'")
            return Response(status_code=status.HTTP_200_OK)

        # 2. ПРОВЕРКА SQUAD
        user_squad_uuid = getattr(user, 'external_squad_uuid', None)
        
        # Fallback для разных форматов ответа SDK
        if user_squad_uuid is None:
             if isinstance(user, dict):
                 user_squad_uuid = user.get('externalSquadUuid')
             elif hasattr(user, 'externalSquadUuid'):
                 user_squad_uuid = user.externalSquadUuid

        # ПРИВЕДЕНИЕ ТИПОВ ДЛЯ СРАВНЕНИЯ (Фикс проблемы с UUID vs str)
        squad_from_api = str(user_squad_uuid).strip() if user_squad_uuid else ""
        squad_allowed = str(settings.allowed_squad_id).strip()

        if squad_from_api == squad_allowed:
            logger.info(f"✅ ACCESS GRANTED (Squad Match): User '{username}'")
            return Response(status_code=status.HTTP_200_OK)
        
        # Отказ
        logger.warning(
            f"⛔ ACCESS DENIED: User '{username}'\n"
            f"   Tag: '{user_tag}' (Expected: '{settings.bypass_tag}')\n"
            f"   Squad: '{squad_from_api}' (Expected: '{squad_allowed}')"
        )
        return Response(status_code=status.HTTP_403_FORBIDDEN)

    except Exception as e:
        # Не спамим в лог ошибками 404 (обычно это запросы favicon/js)
        if "404" not in str(e):
             logger.error(f"API Error checking {short_uuid}: {str(e)}")
        return Response(status_code=status.HTTP_403_FORBIDDEN)

@app.get("/auth-default")
async def verify_default_access(
    x_original_uri: Annotated[str | None, Header()] = None
):
    """Проверка доступа для обычных подписок (default squad)"""
    if not x_original_uri:
        return Response(status_code=status.HTTP_403_FORBIDDEN)

    try:
        # Парсим shortUuid из URL (берем последний сегмент)
        clean_path = x_original_uri.split('?')[0].rstrip('/')
        short_uuid = clean_path.split('/')[-1]
    except Exception:
        logger.error(f"Failed to parse URI: {x_original_uri}")
        return Response(status_code=status.HTTP_403_FORBIDDEN)

    # Простая валидация длины
    if len(short_uuid) < 8:
        return Response(status_code=status.HTTP_403_FORBIDDEN)

    try:
        # Запрашиваем пользователя
        user_response = await client.users.get_user_by_short_uuid(short_uuid)
        user = user_response.response if hasattr(user_response, 'response') else user_response
        
        username = getattr(user, 'username', 'Unknown')
        user_tag = getattr(user, 'tag', None)
        
        # 1. ПРОВЕРКА ADMIN (TAG)
        if user_tag and str(user_tag).strip() == settings.bypass_tag.strip():
            logger.info(f"🔓 ACCESS GRANTED (Admin Tag - Default): User '{username}'")
            return Response(status_code=status.HTTP_200_OK)

        # 2. ПРОВЕРКА DEFAULT SQUAD
        user_squad_uuid = getattr(user, 'external_squad_uuid', None)
        
        # Fallback для разных форматов ответа SDK
        if user_squad_uuid is None:
             if isinstance(user, dict):
                 user_squad_uuid = user.get('externalSquadUuid')
             elif hasattr(user, 'externalSquadUuid'):
                 user_squad_uuid = user.externalSquadUuid

        # ПРИВЕДЕНИЕ ТИПОВ ДЛЯ СРАВНЕНИЯ
        squad_from_api = str(user_squad_uuid).strip() if user_squad_uuid else ""
        squad_default = str(settings.default_squad_id).strip()

        if squad_from_api == squad_default:
            logger.info(f"✅ ACCESS GRANTED (Default Squad): User '{username}'")
            return Response(status_code=status.HTTP_200_OK)
        
        # Отказ
        logger.warning(
            f"⛔ ACCESS DENIED (Default): User '{username}'\n"
            f"   Tag: '{user_tag}' (Expected: '{settings.bypass_tag}')\n"
            f"   Squad: '{squad_from_api}' (Expected Default: '{squad_default}')"
        )
        return Response(status_code=status.HTTP_403_FORBIDDEN)

    except Exception as e:
        # Не спамим в лог ошибками 404 (обычно это запросы favicon/js)
        if "404" not in str(e):
             logger.error(f"API Error checking {short_uuid} (default): {str(e)}")
        return Response(status_code=status.HTTP_403_FORBIDDEN)
