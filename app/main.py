from fastapi import FastAPI, Path, Depends, Body, Header
from app.db_setup import get_db
import uvicorn
from . import model, schemas
from app.model import User
from app.userService import UserService
from fastapi import FastAPI
from datetime import datetime, timedelta
from typing import Dict
from app.schemas import CreateUserSchema, UserSchema, UserLoginSchema, TokenData
from sqlalchemy.orm import Session

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
    return UserService.log_user(payload=payload, session=session)


@app.get("/")
async def get_current_user( authorization = Header(default=None),session: Session = Depends(get_db)):
    return UserService.welcome_user(authorization = authorization,session = session)
