from fastapi import APIRouter, Depends, HTTPException, status
from . import oauth2_scheme
from . import verify_token
from . import get_token_content

worklog = APIRouter(default="/worklog", tags=["worklog"])


@worklog.post("/pause")
def pause_worklog(token: str = Depends(oauth2_scheme)):
    verify_token(token)

    payload = get_token_content(token)
    print(payload)
    return {"status": "Worklog paused"}
