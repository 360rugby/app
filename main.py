from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database import get_db
from models import User as UserModel
from schemas import User as UserSchema, UserCreate as UserCreateSchema
from security import get_password_hash
from typing import List


app = FastAPI()

@app.get("/test_db", response_model=List[UserSchema])
def test_db(db: Session = Depends(get_db)):
    try:
        users = db.query(UserModel).all()
        return [UserSchema.from_orm(user) for user in users]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/users", response_model=UserSchema)
def create_user(user: UserCreateSchema, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(user.Contrasena)
    db_user = UserModel(NombreUsuario=user.NombreUsuario, CorreoElectronico=user.CorreoElectronico, Contrasena=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return UserSchema.from_orm(db_user)
