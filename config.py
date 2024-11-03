    # config.py
import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    MODEL = os.getenv("MODEL")
    MONGO_URI = os.getenv("MONGO_URI")  # Update this URI

