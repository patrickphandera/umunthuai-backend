    # config.py
import os
from dotenv import load_dotenv
load_dotenv()
class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    MODEL = os.getenv("MODEL")
    MONGO_URI = os.getenv("MONGO_URI")  # Update this URI
    

