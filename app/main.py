from fastapi import FastAPI, Path, Depends, Body, Header
from app.db_setup import get_db
import uvicorn
from . import model, schemas
from app.model import User
from app.userService import UserService
from app.auth.jwt_handler import signJWT
from fastapi import FastAPI, status, HTTPException
from jose import JWTError, jwt
from pydantic import BaseModel
from datetime import datetime, timedelta
from passlib.context import CryptContext
from typing import Dict
from app.auth.jwt_handler import decodeJWT
from decouple import config
from app.schemas import CreateUserSchema, UserSchema, UserLoginSchema, TokenData
from sqlalchemy.orm import Session
from app.exceptionHandler import ExceptionHandler

app = FastAPI()
users = []


@app.post('/signup', response_model=UserSchema)
def signup(
    payload: CreateUserSchema = Body(), 
    session:Session=Depends(get_db)
):
    """Processes request to register user account."""
    payload.hashed_password = UserService.hash_password(payload.hashed_password)
    return UserService.create_user(session, user=payload)


@app.post('/login', response_model=Dict)
def login(
        payload: UserLoginSchema = Body(),
        session: Session = Depends(get_db)
    ):
    try:
        user = UserService.get_user(
            session=session, email=payload.email
        )
        print(user)
    except:
        ExceptionHandler.handle_exception()

    is_validated:bool = UserService.validate_password(user, payload.password)
    if not is_validated:
        ExceptionHandler.handle_exception()
    
    return UserService.log_user(user=user, session=session)


@app.get("/")
async def welcome_user( authorization = Header(default=None),session: Session = Depends(get_db)):
    return UserService.welcome_user(authorization = authorization,session = session)
