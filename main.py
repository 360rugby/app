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
from security import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token, create_refresh_token, verify_refresh_token
from dependencies import get_current_role, admin_role_required, user_role_required, admin_or_user_role_required  # new import line
from schemas import Password
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()

# Replace 'your-app-domain.com' with the domain of your Flutter web application,
# or use '*' to allow all origins (not recommended in production)
origins = [
    'http://localhost:54165',  # This seems to be your Flutter web app's origin
    '*',  
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

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
 
#endponit que sirve para crear usuarios con el rol por defecto de User y devuelve datos de la tabla usuario y el token y el token de refresco
@app.post("/users", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    if user.Contrasena != user.ConfirmarContrasena:
        raise HTTPException(
            status_code=400, detail="Passwords do not match"
        )

    db_user_by_name = crud.get_user_by_username(db, user.NombreUsuario)
    db_user_by_email = crud.get_user_by_email(db, user.CorreoElectronico)
    if db_user_by_name or db_user_by_email:
        raise HTTPException(
            status_code=400, detail="Username or email already registered"
        )

    db_user = crud.create_user(db=db, user=user)
    user_roles = [role.to_dict()["NombreRol"] for role in db_user.user_roles]
    data = {"sub": db_user.NombreUsuario, "user_id": db_user.UsuarioID}
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data=data, expires_delta=access_token_expires, user_roles=user_roles
    )

    refresh_token_expires = timedelta(days=7)
    refresh_token = create_refresh_token(
        data=data, expires_delta=refresh_token_expires
    )

    db_user = db_user.to_dict()
    db_user["user_roles_names"] = user_roles
    db_user["access_token"] = access_token
    db_user["refresh_token"] = refresh_token
    return db_user


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

    refresh_token_expires = timedelta(days=7)
    refresh_token = create_refresh_token(
        data=data, expires_delta=refresh_token_expires
    )

    return {
        "access_token": access_token, 
        "refresh_token": refresh_token, 
        "token_type": "bearer", 
        "roles": user_roles
    }

@app.post("/refresh_token", response_model=schemas.Token)
def refresh_token(token: schemas.RefreshToken, db: Session = Depends(get_db)):
    refresh_token_str = token.refresh_token
    user_id = verify_refresh_token(refresh_token_str, db)
    
    user = crud.get_user_by_id(db, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    user_roles = [role.to_dict()["NombreRol"] for role in user.user_roles]
    data = {"sub": user.NombreUsuario, "user_id": user.UsuarioID}
    access_token = create_access_token(
        data=data, expires_delta=access_token_expires, user_roles=user_roles
    )

    refresh_token_expires = timedelta(days=7)
    new_refresh_token = create_refresh_token(
        data=data, expires_delta=refresh_token_expires
    )

    return {
        "access_token": access_token, 
        "refresh_token": new_refresh_token, 
        "token_type": "bearer", 
        "roles": user_roles
    }

# Endpoint que devuelve los datos del usuario autenticado
@app.get("/me", response_model=schemas.UserResponse)
async def read_users_me(current_user: schemas.User = Depends(get_current_user)):
    try:
        user_roles_dict = [user_role.to_dict() for user_role in current_user.user_roles]  # Convertimos los roles a una lista de diccionarios
        user_response = schemas.UserResponse(
            UsuarioID = current_user.UsuarioID,
            NombreUsuario = current_user.NombreUsuario,
            CorreoElectronico = current_user.CorreoElectronico,
            Idioma = current_user.Idioma,
            ZonaHoraria = current_user.ZonaHoraria,
            FechaCreacion = current_user.FechaCreacion,
            FechaActualizacion = current_user.FechaActualizacion,
            Movil = current_user.Movil,
            PuntosLealtad = current_user.PuntosLealtad,
            user_roles = user_roles_dict,  # Usamos la lista de diccionarios de roles que acabamos de crear
            user_roles_names = current_user.user_roles_names
        )
        return user_response
    except Exception as e:
        print(f"An error occurred: {e}")
        raise HTTPException(status_code=500, detail=str(e))


#endpoint que sirve para cambiar la contrseña introduciendo la contraseña antigua
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
#endpoint para cerrar sesion y desloguearse
@app.post("/logout")
def logout(current_user: schemas.User = Depends(get_current_user)):
    """
    This endpoint is used to logout user, even though it doesn't invalidate the token,
    it gives a chance to user interfaces to trigger this endpoint when user wants to logout,
    then UI can delete the token from the local storage.
    """
    return {"detail": "Successfully logged out"}
