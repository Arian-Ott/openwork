from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from typing import Optional
from models.api_models import UserBase, LoginBase, ChangePassword
from models.db_models import DBUser
from models import get_db, SessionLocal
import re
import os
from . import oauth2_scheme

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY")  # Replace with a strong secret key
ALGORITHM = "HS512"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 configuration


# API Router
api_router = APIRouter(default="/auth", tags=["auth"])


# Helper Functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now() + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_hashed_password(password: str) -> str:
    return pwd_context.hash(password)


def get_user(db, username: str):
    return db.query(DBUser).filter(DBUser.username == username).first()


def authenticate_user(db, username: str, password: str):
    """
    Authenticate the user by verifying the password and rehashing if the hash uses an old algorithm.
    """

    user = get_user(db, username)
    if not user:
        return None

    # Check if the password matches the hashed password
    if not pwd_context.verify(password, user.hashed_password):
        return None

    # Check if the hash needs to be updated (e.g., uses old algorithm)
    if pwd_context.needs_update(user.hashed_password):
        user.hashed_password = pwd_context.hash(password)
        db.add(user)
        db.commit()

    return user


def pw_validation(pw):
    if not re.match(
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
        pw,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must include uppercase, lowercase, number, and special character",
        )


# Endpoints
@api_router.post("/token")
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: SessionLocal = Depends(get_db)
):
    # Username and password validation
    if not re.match(r"^[a-zA-Z0-9]*$", form_data.username):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not re.match(
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
        form_data.password,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Authenticate user
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create access token
    access_token = create_access_token(
        data={
            "sub": user.username,
            "id": str(user.id),
            "first_name": user.first_name,
            "last_name": user.last_name,
        }
    )
    return {"access_token": access_token, "token_type": "bearer"}


@api_router.post("/register")
def register(user: UserBase, db: SessionLocal = Depends(get_db)):
    # Username validation
    if not re.match(r"^[a-zA-Z0-9]*$", user.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username must be alphanumeric",
        )
    # Password validation
    pw_validation(user.password)
    # Check if username already exists
    if db.query(DBUser).filter(DBUser.username == user.username).count() > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists"
        )

    # Register new user
    new_user = DBUser(
        username=user.username,
        first_name=user.first_name,
        last_name=user.last_name,
        hashed_password=get_hashed_password(user.password),
    )
    db.add(new_user)
    db.commit()
    return {"status": "User registered successfully"}


@api_router.get("/protected")
def read_protected(
    token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)
):
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

    # Retrieve user details from the database
    user = get_user(db, username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {
        "username": user.username,
        "first_name": user.first_name,
        "last_name": user.last_name,
    }


@api_router.post("/refresh")
def refresh_access_token(token: str = Depends(oauth2_scheme)):
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

    # Generate new access token
    new_access_token = create_access_token(data={"sub": username})
    return {"access_token": new_access_token, "token_type": "bearer"}


@api_router.post("/change_password")
def change_password(
    user: ChangePassword,
    db: SessionLocal = Depends(get_db),
    token: str = Depends(oauth2_scheme),
):
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
    pw_validation(user.old_password)
    pw_validation(user.new_password)
    pw_validation(user.new_password_confirm)

    hash_new_password = get_hashed_password(user.new_password)
    if user.new_password != user.new_password_confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match",
        )
    # Retrieve user details from the database
    user_db = get_user(db, username)
    if user_db is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if the old password is correct
    if not verify_password(user.old_password, user_db.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if verify_password(user.new_password, user_db.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password cannot be the same as the old password",
        )

    # Change password
    user_db.hashed_password = hash_new_password
    db.add(user_db)
    db.commit()
    return {"status": "Password changed successfully"}


@api_router.get("/me")
def read_users_me(
    token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)
):
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
    user = get_user(db, username)

    return {
        "username": user.username,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "id": user.id,
        "account_created": user.account_created,
        "account_updated": user.account_updated,
        "locked": user.locked,
    }
