from typing import List
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from security import ALGORITHM, SECRET_KEY
from database import get_db
import crud
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")  # new line

def get_current_role(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
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
