from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, HTTPException, Header, Depends, Request, Response, HTTPException, Body
from google.auth.exceptions import GoogleAuthError
from firebase import fs, auth as fb_auth
from fastapi import Depends
from pydantic import BaseModel
import os, requests
from datetime import datetime, timezone

app =  FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000","https://sinuapp.netlify.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.getenv("API_KEY")

class UserData(BaseModel):
    name: str | None = None
    email: str
    password: str

class SubscriptionData(BaseModel):
    name: str
    description: str | None = None
    price: float
    currency: str
    subscriptionType: str
    billingDay: int
    billingFrequency: str
    nextPayment: str
    paymentMethod: str
    status: int
    cardBank: str | None = None
    cardFinalNumbers: str | None = None

class SubscriptionUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    price: float | None = None
    currency: str | None = None
    subscriptionType: str | None = None
    billingDay: int | None = None
    billingFrequency: str | None = None
    nextPayment: str | None = None
    paymentMethod: str | None = None
    status: int | None = None
    cardBank: str | None = None
    cardFinalNumbers: str | None = None

@app.get("/")
async def root():
    return {"message": "Hello World"}

def verify_firebase_token(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    id_token = authorization.split(" ", 1)[1]
    try:
        decoded = fb_auth.verify_id_token(id_token)  # verifica assinatura e expiração
        return decoded  # contém uid, email, name, picture, etc.
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token")
    
@app.post("/auth/google")
def login_google(
    res: Response,
    googleIdToken: str | None = Body(default=None, embed=True),
    accessToken: str | None = Body(default=None, embed=True),
):
    if not googleIdToken and not accessToken:
        raise HTTPException(status_code=400, detail="Missing googleIdToken or accessToken")    

    # 1) Troca no Firebase (signInWithIdp)
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key={API_KEY}"   
    if googleIdToken:
        post_body = f"id_token={googleIdToken}&providerId=google.com"                         
    else:
        post_body = f"access_token={accessToken}&providerId=google.com"                       

    payload = {
        "postBody": post_body,
        "requestUri": "https://sinuapp.netlify.app/",
        "returnIdpCredential": True,
        "returnSecureToken": True
    }
    r = requests.post(url, json=payload)                                                       
    if r.status_code != 200:
        msg = r.json().get("error", {}).get("message", "GOOGLE_SIGNIN_FAILED")
        raise HTTPException(status_code=400, detail=msg)

    data = r.json()  # contém idToken, refreshToken, localId, email, displayName...  
    id_token = data["idToken"]                                                       
    refresh = data["refreshToken"]                                                   
    uid = data["localId"]                                                            

    # 2) Cookie HttpOnly com refresh_token (igual ao /login)
    res.set_cookie(
        key="refresh_token",
        value=refresh,
        httponly=True,
        samesite="none",  # Necessário para cross-site
        secure=True,      # Necessário para samesite="none" e HTTPS
        path="/auth",
        max_age=60 * 60 * 24 * 30
    )

    # 3) Upsert no Firestore (opcional)
    try:
        # Tenta pegar o nome do displayName, se não vier, decodifica o token
        user_name = data.get("displayName")
        if not user_name:
            try:
                # Decodifica o token para extrair o nome de dentro dele
                decoded_token = fb_auth.verify_id_token(id_token, check_revoked=False)
                user_name = decoded_token.get("name")
            except Exception:
                user_name = None  # Garante que não quebre se a decodificação falhar

        update_data = {
            "uid": uid,
            "email": data.get("email"),
            "lastLoginAt": datetime.now(timezone.utc).isoformat(),
        }

        # Só adiciona o nome para atualização se ele foi encontrado
        if user_name:
            update_data["name"] = user_name

        fs.collection("accounts").document(uid).set(update_data, merge=True)
    except Exception:
        pass

    return {"idToken": id_token, "uid": uid, "token_type": "Bearer"} 


@app.post("/signup")
async def signup(user: UserData, res: Response):
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={API_KEY}"
    payload = {"email": user.email, "password": user.password, "returnSecureToken": True}
    r = requests.post(url, json=payload)
    if r.status_code != 200:
        msg = r.json().get("error", {}).get("message", "SIGNUP_FAILED")
        raise HTTPException(status_code=400, detail=msg)

    data = r.json()
    uid = data["localId"]

    try:
        fs.collection("accounts").document(uid).set({
            "uid": uid,
            "name": user.name,
            "email": user.email,
            "createdAt": datetime.now(timezone.utc).isoformat(),
        }, merge=True)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # 🔥 seta cookie
    res.set_cookie(
        key="refresh_token",
        value=data["refreshToken"],
        httponly=True,
        samesite="none",  # Necessário para cross-site
        secure=True,      # Necessário para samesite="none" e HTTPS
        path="/auth",
        max_age=60 * 60 * 24 * 30
    )

    return {"idToken": data["idToken"], "uid": uid, "token_type": "Bearer"}

@app.post("/login")
async def login(user: UserData, res: Response):
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"
    payload = {"email": user.email, "password": user.password, "returnSecureToken": True}
    r = requests.post(url, json=payload)

    if r.status_code != 200:
        msg = r.json().get("error", {}).get("message", "LOGIN_FAILED")
        raise HTTPException(status_code=400, detail=msg)

    data = r.json()

    # 🔥 cookie com o refresh (nome padronizado: refresh_token)
    res.set_cookie(
        key="refresh_token",
        value=data["refreshToken"],
        httponly=True,
        samesite="none",  # Necessário para cross-site
        secure=True,      # Necessário para samesite="none" e HTTPS
        path="/auth",
        max_age=60 * 60 * 24 * 30  # 30 dias
    )

    return {"idToken": data["idToken"], "uid": data["localId"], "token_type": "Bearer"}
    
@app.post("/auth/refresh")
def refresh(req: Request, res: Response, refreshToken: str | None = Body(default=None, embed=True)):
    # app (body) OU browser (cookie)
    rt = refreshToken or req.cookies.get("refresh_token")
    if not rt:
        raise HTTPException(status_code=401, detail="No refresh token")

    url = f"https://securetoken.googleapis.com/v1/token?key={API_KEY}"
    form = {"grant_type": "refresh_token", "refresh_token": rt}
    r = requests.post(url, data=form, headers={"Content-Type": "application/x-www-form-urlencoded"})

    if r.status_code != 200:
        # invalida cookie se existir
        res.delete_cookie("refresh_token", path="/auth")
        detail = r.json().get("error", {}).get("message", "INVALID_REFRESH_TOKEN")
        raise HTTPException(status_code=401, detail=detail)

    data = r.json()  # id_token, refresh_token (novo), user_id, expires_in...

    # se veio de cookie, rotacione o cookie
    if req.cookies.get("refresh_token"):
        res.set_cookie(
            key="refresh_token",
            value=data["refresh_token"],
            httponly=True,
            samesite="none",  # Necessário para cross-site
            secure=True,      # Necessário para samesite="none" e HTTPS
            path="/auth",
            max_age=60 * 60 * 24 * 30
        )

    return {"idToken": data["id_token"], "uid": data.get("user_id"), "token_type": "Bearer"}

@app.get("/user/profile")
def get_user_profile(decoded = Depends(verify_firebase_token)):
    uid = decoded.get("uid") or decoded.get("user_id")

    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user = fs.collection("accounts").document(uid).get()
    if not user.exists:
        raise HTTPException(status_code=404, detail="User not found")

    return user.to_dict()

@app.get("/subscription/list")
def list_subscriptions(decoded = Depends(verify_firebase_token)):
    uid = decoded.get("uid") or decoded.get("user_id")

    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    snapshots = fs.collection("accounts").document(uid).collection("subscriptions").stream()

    subscriptions = []
    for sub in snapshots:
        data = sub.to_dict()
        data["id"] = sub.id
        subscriptions.append(data)

    return subscriptions

@app.post("/subscription/add")
def create_subscription(subscription: SubscriptionData, decoded = Depends(verify_firebase_token)):
    uid = decoded.get("uid") or decoded.get("user_id")

    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    try:
        # Cria o documento
        doc_ref = fs.collection("accounts").document(uid).collection("subscriptions").add({
            "user_id": uid,
            "name": subscription.name,
            "description": subscription.description,
            "price": subscription.price,
            "currency": subscription.currency,
            "subscriptionType": subscription.subscriptionType,
            "billingDay": subscription.billingDay,
            "billingFrequency": subscription.billingFrequency,
            "createdDate": datetime.now(timezone.utc).isoformat(),
            "nextPayment": subscription.nextPayment,
            "paymentMethod": subscription.paymentMethod,
            "status": subscription.status,
            "cardBank": subscription.cardBank,
            "cardFinalNumbers": subscription.cardFinalNumbers,
        })

        inserted_id = doc_ref[1].id  # o ID do documento criado

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "detail": "Subscription created successfully",
        "subscription_id": inserted_id
    }

@app.delete("/subscription/delete/{subscription_id}")
def delete_subscription(subscription_id: str, decoded = Depends(verify_firebase_token)):
    uid = decoded.get("uid") or decoded.get("user_id")
    
    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    
    doc_ref = fs.collection("accounts").document(uid).collection("subscriptions").document(subscription_id)
    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Subscription not found")

    try:
        doc_ref.delete()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"detail": "Subscription deleted successfully"}

@app.patch("/subscription/update/{subscription_id}")
def update_subscription(
    subscription_id: str,
    update: SubscriptionUpdate,
    decoded = Depends(verify_firebase_token)
):
    uid = decoded.get("uid") or decoded.get("user_id")

    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    doc_ref = (
        fs.collection("accounts")
          .document(uid)
          .collection("subscriptions")
          .document(subscription_id)
    )

    doc = doc_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Subscription not found")

    # Só pega os campos que realmente vieram no payload
    update_data = update.model_dump(exclude_unset=True)

    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")

    # Atualiza no Firestore
    doc_ref.update(update_data)

    return {"detail": "Subscription updated successfully"}
