from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from security import ALGORITHM, SECRET_KEY
from database import get_db  
import schemas, crud  
from typing import List
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from security import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token
from dependencies import get_current_role, admin_role_required, user_role_required, admin_or_user_role_required  # new import line

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
#funcion que devuelve el rol del usuario atraves del token
def get_current_role(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        roles: List[str] = payload.get("roles")
        if roles is None:
            raise HTTPException(status_code=400, detail="Invalid token")
        return roles
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")
#endpoint que muestra todos los usarios de la tabla usario y la relacion que hay con la tabla de rolesusuarios y usuariosroles
@app.get("/test_db", response_model=List[schemas.User])
def test_db(role: List[str] = Depends(admin_or_user_role_required), db: Session = Depends(get_db)):
    try:
        users = crud.get_users(db)
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
#endponit que sirve para crear usuarios con el rol por defecto de User
@app.post("/users", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    return crud.create_user(db=db, user=user)

@app.post("/token", response_model=schemas.Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = crud.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    user_roles = [role.to_dict()["NombreRol"] for role in user.user_roles]
    access_token = create_access_token(
        data={"sub": user.NombreUsuario}, expires_delta=access_token_expires, user_roles=user_roles
    )
    return {"access_token": access_token, "token_type": "bearer"}
