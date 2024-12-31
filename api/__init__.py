from models import get_db
from fastapi.security import OAuth2PasswordBearer
from fastapi import HTTPException, status
import jwt
from jose import JWTError
import os

SECRET_KEY = os.getenv("SECRET_KEY")  # Replace with a strong secret key
ALGORITHM = "HS512"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

db = get_db()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_token_content(token):

    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    print(payload)
    return payload
