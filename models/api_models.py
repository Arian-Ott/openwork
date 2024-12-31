from pydantic import BaseModel, Field


class UserBase(BaseModel):
    username: str = Field(..., example="johndoe")
    first_name: str = Field(..., example="John")
    last_name: str = Field(..., example="Doe")
    password: str = Field(..., example="Hallo1234!")


class LoginBase(BaseModel):
    username: str = Field(..., example="johndoe")
    password: str = Field(..., example="Hallo1234!")


class SystemLog(BaseModel):
    log_category: str
    comment: str


class ChangePassword(BaseModel):
    old_password: str
    new_password: str
    new_password_confirm: str
