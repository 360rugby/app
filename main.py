from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from database import get_db  
import schemas, crud  
from typing import List

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
#funcion que devuelve el rol del usuario atraves del token
def get_current_role(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user = crud.get_user_by_token(db, token)
    if user is None:
        raise HTTPException(status_code=400, detail="Invalid token")
    return user.user_roles_names
#endpoint que muestra todos los usarios de la tabla usario y la relacion que hay con la tabla de rolesusuarios y usuariosroles
@app.get("/test_db", response_model=List[schemas.User])
def test_db(role: List[str] = Depends(get_current_role), db: Session = Depends(get_db)):
    if 'Admin' not in role:
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        users = crud.get_users(db)
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
#endponit que sirve para crear usuarios con el rol por defecto de User
@app.post("/users", response_model=schemas.User)
def create_user(user: schemas.UserCreate, role: List[str] = Depends(get_current_role), db: Session = Depends(get_db)):
    if 'User' not in role and 'Admin' not in role:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return crud.create_user(db=db, user=user)
