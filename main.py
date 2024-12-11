from fastapi import FastAPI,Request, status
from pydantic_settings import BaseSettings
from sqlalchemy.orm import Session,column_property
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI,Response,status,HTTPException,Depends, APIRouter
from fastapi.security.oauth2 import OAuth2PasswordRequestForm
from typing import List
from sqlalchemy import func
from sqlalchemy.sql import text
import sqlalchemy as bb
from jose import JWTError,jwt
from datetime import datetime, timedelta, timezone
from fastapi import Depends,status,HTTPException
from fastapi.security import OAuth2PasswordBearer
oauth2_scheme= OAuth2PasswordBearer(tokenUrl='login')
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import psycopg2
import time
from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.sql.sqltypes import TIMESTAMP, DATE
from sqlalchemy.sql.expression import text 
from sqlalchemy import func
from sqlalchemy.orm import column_property
from pydantic import BaseModel, validator
from datetime import date,datetime
from typing import Optional
from pydantic.types import conint
from passlib.hash import pbkdf2_sha256



# #TO CHECK ALL THE ENVIRONMENT VARIABLES ARE THERE
class Settings(BaseSettings):#checks local environment variablea (IN THE HOST)to see if the following variables are there
    database_str:str
    secret_key:str
    algorithm:str

    class Config:
       env_file=".env"


settings= Settings()


DATABASE_URL=settings.database_str
engine = create_engine(DATABASE_URL)
sessionlocal= sessionmaker(autocommit=False, autoflush=False, bind=engine)

base= declarative_base()

def get_db():
   db= sessionlocal()
   try:
      yield db
   finally:
      db.close()
 



class User(base):
    __tablename__='users'
    id=Column(Integer,primary_key=True,nullable=False) 
    username=Column(String(100),nullable=False,unique=True)
    email=Column(String(200),nullable=False,unique=True)
    password=Column(String(400),nullable=False)



class Token(BaseModel):
    access_token:str
    token_type:str

class TokenData(BaseModel):
    id:Optional[str] = None

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username:str
    password:str

class UserResponce(BaseModel):
    id: int
    username: str
    email: str

    class Config:
        orm_mode = True


class clientin(BaseModel):
    name:str
   
class responseclient(BaseModel):
    id:int
    name:Optional[str]= None
   
    class Config:
        orm_mode=True


class clientID(BaseModel):
    id:int 
    class Config:
        orm_mode=True





SECRET_KEY=settings.secret_key
ALGORITHM = settings.algorithm


def create_access_token(data:dict):
   to_encode= data.copy()
   expire = datetime.now(timezone.utc) + timedelta(days=6 * 30) 
   to_encode.update({'exp':expire})
   encoded_jwt= jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM) #(datalode, secret key, algorithm)
   return encoded_jwt


def verify_access_token(token:str,credentials_exceptions):
    try:
        payload=jwt.decode(token, SECRET_KEY,algorithms=[ALGORITHM])
        id:str=payload.get("user_id")

        if  id is None:
           raise credentials_exceptions
        token_data=TokenData(id=id)

    except JWTError:  
        raise credentials_exceptions
    
    return token_data
    
def get_current_user(token:str = Depends(oauth2_scheme), db:Session=Depends(get_db)):
    credentials_exceptions=HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Could not validate credentials",headers={"WWW-Authrnticate":"Bearer"})   
    
    token= verify_access_token(token,credentials_exceptions)
    user=db.query(User).filter(User.id==token.id).first()

    return user





def hash(password:str):
    
    return pbkdf2_sha256.hash(password)


def verify(plain_pass,harsh_pass):#fun gives the value of true or false
    print(plain_pass)
    print(harsh_pass)
    
    x =pbkdf2_sha256.verify(plain_pass, harsh_pass)
    
   
    return x






base.metadata.create_all(bind=engine)
app=FastAPI()
# handler=Mangum(app)
# origions=["*"] 
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],#domains which 
    allow_credentials=True,
    allow_methods=["*"],# allow specific mehods(get,update)
    allow_headers=["*"],#allwo which headers
)

@app.get('/')
def home():
   return{
      "message":"we are in home baby"
   }



@app.post("/users",status_code=status.HTTP_201_CREATED, response_model=UserResponce)
def create_user(new_user:UserCreate,db: Session = Depends(get_db)):
   #has the password- user.passowrd
   existing_user = db.query(User).filter(User.email == new_user.email).first()
   if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already registered",
        )
   hashed_password=hash(new_user.password)
   new_user.password= hashed_password
   
   user=User(**new_user.model_dump())
   db.add(user)
   db.commit()
   return user





@app.post('/auth')
def login( user_credentials:UserLogin, db:Session = Depends(get_db)):
 user = db.query(User).filter(User.username == user_credentials.username).first()
 username = db.query(User.username).filter(User.username == user_credentials.username).first()
 if not user:
  raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail=f"invalid credentials")
 
 if not verify( user_credentials.password,user.password): #if it is true, returns token,,,,if not it raises an exception
  raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid credentials")

 access_token=create_access_token(data={"user_id": user.id})
 print(access_token)
 return{"token": access_token, "token_type":"bearer","user_name":user.username}

