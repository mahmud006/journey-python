from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    name: str
    password: str
    email: EmailStr
class LoginRequest(BaseModel):
    email: EmailStr
    password: str
class Token(BaseModel):
    access_token: str
    token_type: str
