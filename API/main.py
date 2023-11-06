from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

SECRET_KEY = "960dc89228ad462aaa724e88e3e380a734a0c7c89a868b3c4930a988bf8c1de9"
ALGORITHM = "HS256"
ACESS_TOKEN_EXPIRE_MINUTES = 30

fake_db ={
    "ivo": {
        "username":"ivo",
        "full_name": "Ivo Pimenta",
        "email": "ivo@gmial.com",
        "hashed_password":"",
        "disabled": False
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str or None = None

class User(BaseModel):
    username: str
    email: str or None = None
    full_name: str or None = None
    disabled: bool or None = None

class UserInDB(User):
    hashed_password : str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated = "auto")
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl = "token")

app = FastAPI()

def verify_password (plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_data = db[username]
        return UserInDB(**user_data)
    
def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_acess_token (data: dict, expires_delta: timedelta or None = None):
    to_encode = data.copy()





