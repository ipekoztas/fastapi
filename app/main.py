from fastapi import FastAPI, Path, Depends, Body, Header
from app.db_setup import get_db
import uvicorn
from . import model, schemas
from app.model import User
from app.auth.jwt_handler import signJWT
from sqlalchemy.orm import Session
from fastapi import FastAPI, status, HTTPException
from jose import JWTError, jwt
from pydantic import BaseModel
from datetime import datetime, timedelta
from passlib.context import CryptContext
from typing import Dict
from app.auth.jwt_handler import decodeJWT
from decouple import config
from app.schemas import CreateUserSchema, UserSchema, UserLoginSchema, TokenData

app = FastAPI()
users = []

def create_user(session:Session, user:CreateUserSchema):
    db_user = User(**user.dict())
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user

def get_user(session:Session, email:str):
    return session.query(User).filter(User.email == email).one()



@app.post('/signup', response_model=UserSchema)
def signup(
    payload: CreateUserSchema = Body(), 
    session:Session=Depends(get_db)
):
    """Processes request to register user account."""
    payload.hashed_password = User.hash_password(payload.hashed_password)
    return create_user(session, user=payload)


@app.post('/login', response_model=Dict)
def login(
        payload: UserLoginSchema = Body(),
        session: Session = Depends(get_db)
    ):
    try:
        user = get_user(
            session=session, email=payload.email
        )
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user credentials"
        )

    is_validated:bool = user.validate_password(payload.password)
    if not is_validated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user credentials"
        )
    user.is_active = True
    session.commit()
    return user.generate_token()


JWT_SECRET =config("secret")

"""
def read_root(token:str):
    a = get_db()
    return {"Hello" :"World"}"""
@app.get("/")
async def get_current_user( authorization = Header(default=None),session: Session = Depends(get_db)):
    print(authorization)
    token = authorization.split(" ")[1]
    print(token)
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET)
        username: str = payload.get("full_name")
        print(username)
        email: str = payload.get("email")
        print(email)
        if username is None:
            raise credentials_exception
        #token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(session=session, email=email)
    if user is None:
        raise credentials_exception
    return {"Hello" :username}
