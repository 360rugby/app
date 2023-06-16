from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db  # Asegúrate de que el import es correcto
import schemas, crud  # Importa tus esquemas y funciones de crud
from typing import List

app = FastAPI()

@app.get("/test_db", response_model=List[schemas.User])
def test_db(db: Session = Depends(get_db)):
    try:
        users = crud.get_users(db)  # Debes definir esta función en tu archivo crud
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/users", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    return crud.create_user(db=db, user=user)
