from fastapi import APIRouter, Depends, HTTPException, status, Response,Request
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from .schemas import UserCreate, Token, LoginRequest
from .models import UserInDB
from app.core.database import users_collection
from app.core.security import verify_password, get_password_hash, create_tokens, verify_refresh_token, handle_refresh_token
from .dependencies import get_current_user

auth_router = APIRouter()

ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

@auth_router.post("/signup")
async def signup(user_data: UserCreate, response: Response):
    user = users_collection.find_one({"email": user_data.email})  # Check by email
    if user:
        raise HTTPException(status_code=400, detail="Email already registered")  # Update error message

    # Hash password
    hashed_password = get_password_hash(user_data.password)

    # Insert user details into the database
    users_collection.insert_one({
        "email": user_data.email,  # Store email as unique identifier
        "hashed_password": hashed_password,
        "name": user_data.name  # Store name
    })

    # Create JWT token
    access_token, refresh_token = create_tokens({"sub": user_data.email, "name": user_data.name,})  # Use email as subject
    # Set the access and refresh tokens as HTTP-only cookies
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevent JavaScript access
        secure=True,  # Only allow over HTTPS
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # Expire in 15 minutes
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,  # Expire in 7 days
    )

    return {"message": "User registered successfully"}


@auth_router.post("/login")
async def login(user_data: LoginRequest, response: Response):
    # Find the user by email
    user = users_collection.find_one({"email": user_data.email})

    # Check if the user exists and if the password matches
    if not user or not verify_password(user_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Create a JWT access token using email as the subject
    access_token, refresh_token = create_tokens({"sub": user_data.email, "name": user['name'],})

    # Set the access and refresh tokens as HTTP-only cookies
    response.set_cookie(
        key="access_token",
        value=access_token,
        # httponly=True,  # Prevent access from JavaScript
        # secure=True,  # HTTPS only
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        # httponly=True,
        # secure=True,
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
    )
    # Return the token
    return {"message": "Login successful"}


@auth_router.post("/refresh", response_model=Token)
async def refresh_token(request: Request, response: Response):
    # Extract refresh token from cookies
    refresh_token = request.cookies.get("refresh_token")

    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token missing")

    # Delegate the handling of the refresh token to the security function
    return await handle_refresh_token(refresh_token, response)

@auth_router.post("/logout")
async def logout(current_user: UserInDB = Depends(get_current_user)):
    # Invalidate the refresh token in the database
    users_collection.update_one(
        {"email": current_user.email},
        {"$unset": {"refresh_token": ""}}  # Remove refresh token
    )
    return {"msg": "Successfully logged out"}


@auth_router.get("/me")
async def get_profile(current_user: UserInDB = Depends(get_current_user)):
    return current_user
