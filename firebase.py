import os
from dotenv import load_dotenv

load_dotenv()

import firebase_admin
from firebase_admin import credentials, firestore, auth as admin_auth

CLIENT_EMAIL = os.getenv("CLIENT_EMAIL")
PRIVATE_KEY  = (os.getenv("PRIVATE_KEY") or "").replace("\\n", "\n")
PROJECT_ID   = os.getenv("PROJECT_ID")
assert CLIENT_EMAIL and PRIVATE_KEY and PROJECT_ID, "Faltam variáveis no .env"

# Monta o “service account” mínimo (sem precisar do arquivo .json)
service_account_info = {
    "type": "service_account",
    "project_id": PROJECT_ID,
    "private_key": PRIVATE_KEY,
    "client_email": CLIENT_EMAIL,
    "token_uri": "https://oauth2.googleapis.com/token",
}

cred = credentials.Certificate(service_account_info)

if not firebase_admin._apps:
    firebase_admin.initialize_app(cred, {"projectId": PROJECT_ID})

fs = firestore.client()
auth = admin_auth