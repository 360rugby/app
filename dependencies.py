from typing import List
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from security import ALGORITHM, SECRET_KEY
from database import get_db
from crud import get_user_by_token
from fastapi.security import OAuth2PasswordBearer
from schemas import TokenData

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise credentials_exception
        token_data = TokenData(user_id=user_id)
    except JWTError:
        raise credentials_exception
    user = get_user_by_token(db, token_data.user_id)
    if user is None:
        raise credentials_exception
    return user

def get_current_role(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        roles: List[str] = payload.get("roles")
        if roles is None:
            raise HTTPException(status_code=400, detail="Invalid token")
        return roles
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")

def admin_role_required(role: List[str] = Depends(get_current_role)):
    if 'Admin' not in role:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return role

def user_role_required(role: List[str] = Depends(get_current_role)):
    if 'User' not in role:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return role

def admin_or_user_role_required(role: List[str] = Depends(get_current_role)):
    if 'Admin' not in role and 'User' not in role:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return role
