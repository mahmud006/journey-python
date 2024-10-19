from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from .models import UserInDB
from .schemas import Token
from app.core.security import decode_access_token, verify_access_token
from app.core.database import users_collection

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    try:
        # Verify the token
        payload = verify_access_token(token)
        user_email = payload.get("sub")
        if user_email is None:
            print("User email not found in token")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

        # Retrieve the user from the database
        user = users_collection.find_one({"email": user_email})
        if user is None:
            print("User not found in database")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

        return UserInDB(**user)  # Return user object
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token verification failed")
