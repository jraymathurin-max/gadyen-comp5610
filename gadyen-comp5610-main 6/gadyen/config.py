"""Central configuration, read from environment variables (.env file in development)."""
import os

from dotenv import load_dotenv

load_dotenv()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
MODEL = os.getenv("GADYEN_MODEL", "claude-sonnet-5-5")
MAX_STEPS = int(os.getenv("GADYEN_MAX_STEPS", "25"))
DB_PATH = os.getenv("GADYEN_DB_PATH", "gadyen.db")
DEV_KEY = os.getenv("GADYEN_DEV_KEY", "")

LANGUAGES = {"en": "English", "es": "Spanish", "fr": "French", "ht": "Haitian Creole"}
