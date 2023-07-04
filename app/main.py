from fastapi import FastAPI, Path
from app.db_setup import get_db
import uvicorn
from app.model import User
app = FastAPI()
users = []

@app.get("/")
def read_root():
    a = get_db()
    return {"Hello" :"World"}
@app.post('/register', status_code=201)
def register():
    
    return{}


@app.post('/login')
def login():
    return {}


@app.get('/unprotected')
def unprotected():
    return { 'hello': 'world' }


@app.get('/protected')
def protected():
    return {  }