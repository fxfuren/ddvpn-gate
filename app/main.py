import logging
from typing import Annotated
from fastapi import FastAPI, Header, Response, status
from remnawave import RemnawaveSDK
from app.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("remnagate")

app = FastAPI(title="RemnaGate", version="1.0.3")

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
        clean_path = x_original_uri.split('?')[0].rstrip('/')
        short_uuid = clean_path.split('/')[-1]
    except Exception:
        logger.error(f"Failed to parse URI: {x_original_uri}")
        return Response(status_code=status.HTTP_403_FORBIDDEN)

    if len(short_uuid) < 8:
        return Response(status_code=status.HTTP_403_FORBIDDEN)

    try:
        # Получаем пользователя
        user_response = await client.users.get_user_by_short_uuid(short_uuid)
        user = user_response.response if hasattr(user_response, 'response') else user_response
        
        username = getattr(user, 'username', 'Unknown')
        user_tag = getattr(user, 'tag', None)
        
        if user_tag == settings.bypass_tag:
            logger.info(f"🔓 ACCESS GRANTED (Admin Tag): User '{username}'")
            return Response(status_code=status.HTTP_200_OK)

        user_squad_uuid = getattr(user, 'external_squad_uuid', None)
        
        if user_squad_uuid is None:
             if isinstance(user, dict):
                 user_squad_uuid = user.get('externalSquadUuid')
             elif hasattr(user, 'externalSquadUuid'):
                 user_squad_uuid = user.externalSquadUuid

        if user_squad_uuid == settings.allowed_squad_id:
            logger.info(f"✅ ACCESS GRANTED (Squad Match): User '{username}'")
            return Response(status_code=status.HTTP_200_OK)
        
        # Отказ
        logger.warning(
            f"⛔ ACCESS DENIED: User '{username}' | "
            f"Tag: {user_tag} | Squad: {user_squad_uuid}"
        )
        return Response(status_code=status.HTTP_403_FORBIDDEN)

    except Exception as e:
        logger.error(f"API Error checking {short_uuid}: {str(e)}")
        return Response(status_code=status.HTTP_403_FORBIDDEN)
