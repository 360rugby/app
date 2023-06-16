from typing import List
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models import User
from schemas import User as UserSchema

app = FastAPI()

@app.get("/test_db", response_model=List[UserSchema])
def test_db(db: Session = Depends(get_db)):
    try:
        users = db.query(User).all()
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
