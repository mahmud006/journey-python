from pydantic import BaseModel

class UserInDB(BaseModel):
    username: str
    hashed_password: str
