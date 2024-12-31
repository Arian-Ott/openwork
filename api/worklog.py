from fastapi import APIRouter, Depends, HTTPException, status
from . import oauth2_scheme
from . import verify_token
from . import get_token_content
from models.db_models import DBUser, TimeLog, SystemLog
from models import SessionLocal
from models import get_db
from datetime import datetime
import pandas as pd
from fastapi.responses import StreamingResponse
import io
worklog = APIRouter(default="/worklog", tags=["worklog"])

def convert_to_date(date_string: str):
    return datetime.strptime(date_string, "%Y-%m-%d")
def check_if_workday_started(user_id: int, db: SessionLocal):
    return db.query(TimeLog).filter(TimeLog.user_id == user_id, TimeLog.date == datetime.now().date(), TimeLog.short_desc == "SYSTEM", TimeLog.comment == "Workday started").first()
def check_if_workday_paused(user_id: int, db: SessionLocal):
    return db.query(TimeLog).filter(TimeLog.user_id == user_id, TimeLog.date == datetime.now().date(), TimeLog.short_desc == "SYSTEM", TimeLog.comment == "Workday paused").first()

@worklog.post("/start-workday")
def start_workday(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    verify_token(token)
    user = get_token_content(token).get("sub")
    user_id = db.query(DBUser).filter(DBUser.username == user).first().id
    if db.query(TimeLog).filter(TimeLog.user_id == user_id, TimeLog.date == datetime.now().date()).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Workday already started")

    new_log = TimeLog(user_id=user_id, short_desc="SYSTEM", comment="Workday started")
    db.add(new_log)
    db.commit()

    return {"status": "Workday started"}

@worklog.post("/pause")
def pause_worklog(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    verify_token(token)

    payload = get_token_content(token).get("sub")
    user = db.query(DBUser).filter(DBUser.username == payload).first()
    if not check_if_workday_started(user.id, db):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Workday not started")
    if check_if_workday_paused(user.id, db):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Workday already paused")
    new_log = TimeLog(user_id=user.id, short_desc="SYSTEM", comment="Workday paused")
    db.add(new_log)
    db.commit()

    return {"status": "Worklog paused"}


@worklog.post("/resume")
def resume_worklog(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    verify_token(token)

    payload = get_token_content(token).get("sub")
    user = db.query(DBUser).filter(DBUser.username == payload).first()
    if not check_if_workday_started(user.id, db):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Workday not started")
    if not check_if_workday_paused(user.id, db):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Workday not paused")
    new_log = TimeLog(user_id=user.id, short_desc="SYSTEM", comment="Workday resumed")
    db.add(new_log)
    db.commit()

    return {"status": "Worklog resumed"}

@worklog.post("/end-workday")
def end_workday(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    verify_token(token)

    payload = get_token_content(token).get("sub")
    user = db.query(DBUser).filter(DBUser.username == payload).first()
    if not check_if_workday_started(user.id, db):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Workday not started")
    if check_if_workday_paused(user.id, db):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Workday paused")
    new_log = TimeLog(user_id=user.id, short_desc="SYSTEM", comment="Workday ended")
    db.add(new_log)
    db.commit()

    return {"status": "Workday ended"}

@worklog.post("/comment")
def add_comment(comment: str, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    verify_token(token)

    payload = get_token_content(token).get("sub")
    user = db.query(DBUser).filter(DBUser.username == payload).first()
    if not check_if_workday_started(user.id, db):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Workday not started")
    
    new_log = TimeLog(user_id=user.id, short_desc="USER_COMMENT", comment=comment)
    db.add(new_log)
    db.commit()

    return {"status": "Comment added"}

@worklog.get("/get-timelog")
def get_timelog(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    verify_token(token)

    payload = get_token_content(token).get("sub")
    user = db.query(DBUser).filter(DBUser.username == payload).first()
    if not check_if_workday_started(user.id, db):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Workday not started")
    
    timelogs = db.query(TimeLog).filter(TimeLog.user_id == user.id).all()
    timelogs = {"username": user.username, "id": user.id, "first_name": user.first_name, "last_name": user.last_name, "entries": timelogs }
    return timelogs

@worklog.get("/get-timelog-by-date")
def get_timelog_by_date(date: str, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    verify_token(token)

    payload = get_token_content(token).get("sub")
    user = db.query(DBUser).filter(DBUser.username == payload).first()
    if not check_if_workday_started(user.id, db):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Workday not started")
    
    timelogs = db.query(TimeLog).filter(TimeLog.user_id == user.id, TimeLog.date == convert_to_date(date)).all()
    return timelogs

@worklog.get("/worked-time")
def get_worked_time(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    verify_token(token)

    payload = get_token_content(token).get("sub")
    user = db.query(DBUser).filter(DBUser.username == payload).first()
    if not check_if_workday_started(user.id, db):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Workday not started")
    
    timelogs = db.query(TimeLog).filter(TimeLog.user_id == user.id).all()
    return {"worked_time": len(timelogs)}


@worklog.get("/worked-time/csv")
def get_worked_time_csv(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    # Verify and decode token
    verify_token(token)
    payload = get_token_content(token).get("sub")
    user = db.query(DBUser).filter(DBUser.username == payload).first()

    if not check_if_workday_started(user.id, db):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Workday not started")
    
    # Fetch time logs and create a DataFrame
    timelogs = db.query(TimeLog).filter(TimeLog.user_id == user.id).all()
    df = pd.DataFrame([log.__dict__ for log in timelogs])
    
    # Drop SQLAlchemy metadata and convert to CSV
    df.drop(columns=["_sa_instance_state"], inplace=True, errors="ignore")
    csv_data = io.StringIO()
    df.to_csv(csv_data, index=False)
    csv_data.seek(0)

    # Return CSV as a streaming response
    return StreamingResponse(
        iter([csv_data.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=worked_time.csv"
        }
    )