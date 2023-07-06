from app.model import User
from decouple import config
from sqlalchemy.orm import Session
from app.schemas import CreateUserSchema, UserSchema, UserLoginSchema, TokenData
from datetime import datetime, timedelta
from jose import jwt
import bcrypt
from sqlalchemy.orm import Session
from app.exceptionHandler import ExceptionHandler
from jose import JWTError, jwt
from fastapi import FastAPI, Path, Depends, Body, Header


JWT_SECRET =config("secret")
JWT_ALGORITHM = config("algorithm")

class UserService():

    def create_user(session:Session, user:CreateUserSchema):
        db_user = User(**user.dict())
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
        return db_user

    def get_user(session:Session, email:str):
        return session.query(User).filter(User.email == email).one()

    @staticmethod
    def hash_password(password) -> str:
        """Transforms password from it's raw textual form to 
        cryptographic hashes
        """
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    @staticmethod
    def validate_password(user : User, password) -> bool:
        """Confirms password validity"""
        return {
            "access_token": jwt.encode(
                {"full_name": user.full_name, "email": user.email},
                "ApplicationSecretKey"
            )
        }

    @staticmethod
    def generate_token(user : User) -> dict:
        """Generate access token for user"""
        expiration = datetime.utcnow() + timedelta(minutes=15)

        payload = {
            "full_name": user.full_name,
            "email": user.email,
            "exp": expiration
        }
        return {
            "access_token": jwt.encode(payload, JWT_SECRET)
        }
    
    @staticmethod
    def log_user(user: User, session: Session):
        user.is_active = True
        session.commit()
        return UserService.generate_token(user)

    @staticmethod
    def welcome_user(authorization ,session: Session ):
        token = str(authorization).split(" ")[1]
        try:
            payload = jwt.decode(token, JWT_SECRET)
            username: str = payload.get("full_name")
            email: str = payload.get("email")
            if username is None:
                ExceptionHandler.credentials_exception()
        except JWTError:
            ExceptionHandler.credentials_exception()
        user = UserService.get_user(session=session, email=email)
        if user is None:
            ExceptionHandler.credentials_exception()
        return {"Hello" :username}