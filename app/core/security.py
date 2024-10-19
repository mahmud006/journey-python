import os
from datetime import datetime, timedelta

from fastapi import HTTPException, status, Response
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv

from app.api.auth.schemas import Token

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-if-not-set")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_tokens(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    access_token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    refresh_expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token_payload = {"sub": data.get("sub"), "exp": refresh_expire}  # Include email in the refresh token
    refresh_token = jwt.encode(refresh_token_payload, SECRET_KEY, algorithm=ALGORITHM)

    return access_token, refresh_token

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def verify_access_token(token: str):
    try:
        # Decode the token, verifying its signature and expiration
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Extract token expiry time (optional, but recommended)
        expire = payload.get("exp")
        if expire and datetime.utcfromtimestamp(expire) < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Return the payload if everything is valid (e.g., token subject, expiration, etc.)
        return payload

    except JWTError:
        # This will catch any errors related to invalid tokens (tampered, invalid signature, etc.)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
def verify_refresh_token(refresh_token: str):
    try:
        # Decode the refresh token using the secret key and the specified algorithm
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

        # Check if the token has expired
        if 'exp' in payload:
            if datetime.utcnow() > datetime.fromtimestamp(payload['exp']):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")

        # Check if the subject (email) is present in the payload
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token: Email not found")

        return payload  # Return the decoded payload for further processing

    except JWTError:
        # Catch JWTError to handle any decoding issues
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")


async def handle_refresh_token(refresh_token: str, response: Response) -> Token:
    payload = verify_refresh_token(refresh_token)  # Verify the refresh token
    email = payload.get("sub")  # Extract the email from the payload

    # Proceed to create new access and refresh tokens
    access_token, new_refresh_token = create_tokens({"sub": email})  # Include email when creating tokens

    # Set the new refresh token in the cookie
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=True,
        max_age=7 * 24 * 60 * 60,  # 7 days expiry
    )

    return Token(access_token=access_token, token_type="bearer")
