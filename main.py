from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from dependencies import get_current_user
from models import User
from schemas import RefreshToken
from security import ALGORITHM, SECRET_KEY
from database import get_db  
import schemas, crud  
from typing import List
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from security import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token
from dependencies import get_current_role, admin_role_required, user_role_required, admin_or_user_role_required  # new import line
from schemas import Password



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
#endpoint que muestra todos los usuarios de la tabla usuario y la relacion que hay con la tabla de rolesusuarios y usuariosroles
@app.get("/test_db", response_model=List[schemas.User])
def test_db(role: List[str] = Depends(admin_or_user_role_required), db: Session = Depends(get_db)):
    try:
        users = crud.get_users(db)
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.get("/allusers", response_model=List[schemas.User])
def test_db(current_user: schemas.User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        users = crud.get_users(db)
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
 
#endponit que sirve para crear usuarios con el rol por defecto de User
@app.post("/users", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    return crud.create_user(db=db, user=user)
#endpoint que sirve para iniciar sesion con el username y el password y devuelve el token de acceso
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
    data = {"sub": user.NombreUsuario, "user_id": user.UsuarioID}
    access_token = create_access_token(
        data=data, expires_delta=access_token_expires, user_roles=user_roles
    )

    refresh_token_expires = timedelta(days=7)  # Set this to whatever you want
    refresh_token = create_access_token(
        data=data, expires_delta=refresh_token_expires, user_roles=user_roles
    )

    # Store refresh token in user model
    user.RefreshToken = refresh_token
    user.RefreshTokenExpiry = datetime.utcnow() + refresh_token_expires
    db.commit()

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.post("/refresh_token", response_model=schemas.Token)
def refresh_token(token: schemas.RefreshToken, db: Session = Depends(get_db)):
    refresh_token = token.refresh_token
    user = crud.get_user_by_refresh_token(db, refresh_token)
    if user is None or user.RefreshTokenExpiry < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    user_roles = [role.to_dict()["NombreRol"] for role in user.user_roles]
    data = {"sub": user.NombreUsuario, "user_id": user.UsuarioID}
    access_token = create_access_token(
        data=data, expires_delta=access_token_expires, user_roles=user_roles
    )
    
    refresh_token_expires = timedelta(days=7)  # Set this to whatever you want
    new_refresh_token = create_access_token(
        data=data, expires_delta=refresh_token_expires, user_roles=user_roles
    )
    
    # Store new refresh token in user model
    user.RefreshToken = new_refresh_token
    user.RefreshTokenExpiry = datetime.utcnow() + refresh_token_expires
    db.commit()

    return {"access_token": access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}

@app.post("/change_password")
def change_password(
    password: Password, 
    current_user: schemas.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not crud.verify_password(password.old_password, current_user.Contrasena):
        raise HTTPException(status_code=400, detail="Incorrect old password")

    try:
        crud.change_password(db=db, user=current_user, new_password=password.new_password)
        return {"message": "Password changed successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/logout")
def logout(current_user: schemas.User = Depends(get_current_user)):
    """
    This endpoint is used to logout user, even though it doesn't invalidate the token,
    it gives a chance to user interfaces to trigger this endpoint when user wants to logout,
    then UI can delete the token from the local storage.
    """
    return {"detail": "Successfully logged out"}
