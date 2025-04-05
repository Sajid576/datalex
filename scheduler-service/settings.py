import os
from dotenv import load_dotenv

load_dotenv()

HOST = os.environ.get("HOST")
PORT = int(os.environ.get("PORT"))
IS_DEV = os.environ.get("IS_DEV") in ["True", "true"]

# Gmail API configs
CREDENTIALS_PATH = os.environ.get("CREDENTIALS_PATH")
GOOGLE_DRIVE_CREDENTIALS_PATH = os.environ.get("GOOGLE_DRIVE_CREDENTIALS_PATH")
TOKEN_PATH = os.environ.get("TOKEN_PATH")
GITHUB_REPO_URL = os.environ.get("GITHUB_REPO_URL")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
TEMP_PATH = os.environ.get("TEMP_PATH")
TARGET_GOOGLE_DRIVE_PATH = os.environ.get("TARGET_GOOGLE_DRIVE_PATH")
SURICATA_LOG_TARGET_PATH = os.environ.get("SURICATA_LOG_TARGET_PATH")
SURICATA_LOG_CHUNK_SIZE = os.environ.get("SURICATA_LOG_CHUNK_SIZE")
