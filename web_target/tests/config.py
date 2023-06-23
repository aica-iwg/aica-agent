import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    JUICE_URL = os.getenv("JUICE_URL")

config = Config()