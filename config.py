from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


class Config:
    DATABASE = BASE_DIR / "instance" / "splyntara.db"