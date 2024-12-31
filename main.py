import requests as req
import os
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.auth import api_router
from api.worklog import worklog


from models import recreate_db

load_dotenv()


def startup_tasks():
    recreate_db()


app = FastAPI()

if os.getenv("DEBUG") == "True":
    pass

origins = [
    "http://localhost:3000",
    "http://localhost",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)
app.include_router(worklog)
