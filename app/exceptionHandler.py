from app.model import User
from app.userService import UserService
from fastapi import FastAPI, status, HTTPException

class ExceptionHandler():
# this class handles exceptions
    @staticmethod
    def handle_exception():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user credentials"
        )
