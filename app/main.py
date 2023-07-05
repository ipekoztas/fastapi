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

"""
def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()


def create_user(db: Session, user: schemas.UserCreate):
    fake_hashed_password = user.password + "notreallyhashed"
    db_user = models.User(email=user.email, hashed_password=fake_hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

"""

"""
@app.post('/register', status_code=201)
def register(user: User, db: Session = Depends(get_db)):
    # Check if the user already exists
    if check_user(user, db):
        return {"message": "User already exists"}

    # Save the user to the database
    db.add(user)
    db.commit()

    # Return the JWT token response
    return signJWT(user.email)

def check_user(data: User, db: Session):
    # Query the database to check if the provided email already exists
    existing_user = db.query(User).filter(User.email == data.email).first()
    return existing_user is not None





# replace it with your 32 bit secret key
SECRET_KEY = "bb9fad4508f673f74182398173b9d3b0"

# encryption algorithm
ALGORITHM = "HS256"

# Pydantic Model that will be used in the
# token endpoint for the response
class Token(BaseModel):
	access_token: str
	token_type: str



# this function will create the token
# for particular data
def create_access_token(data: dict):
	to_encode = data.copy()
	
	# expire time of the token
	expire = datetime.utcnow() + timedelta(minutes=15)
	to_encode.update({"exp": expire})
	encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
	
	# return the generated token
	return encoded_jwt

# the endpoint to get the token
@app.get("/get_token")
async def get_token():

	data = {
		'info': 'secret information',
		'from': 'GFG'
	}
	token = create_access_token(data=data)
	return {'token': token}

# the endpoint to verify the token
@app.post("/verify_token")
async def verify_token(token: str):
	try:
		payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
		return payload
	except JWTError:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Could not validate credentials",
		)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

@app.post('/register', status_code=201)
def register(user: User, db: Session = Depends(get_db)):
    # Check if the user already exists
    if check_user(user, db):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")

    # Generate hashed password
    hashed_password = get_password_hash(user.password)
    user.hashed_password = hashed_password

    # Save the user to the database
    db.add(user)
    db.commit()
    db.refresh(user)

    # Return the JWT token response
    return signJWT(user.email)

def check_user(data: User, db: Session):
    # Query the database to check if the provided email already exists
    existing_user = db.query(User).filter(User.email == data.email).first()
    return existing_user is not None
    """