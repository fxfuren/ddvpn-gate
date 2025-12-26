from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    remnawave_base_url: str
    remnawave_token: str
    allowed_squad_id: str
    bypass_tag: str = "ADMIN"

    class Config:
        env_file = ".env"

settings = Settings()
