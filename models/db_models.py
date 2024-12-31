from . import Base
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
    UUID,
    func,
    Boolean,
    DATE,
)
from datetime import datetime
from uuid import uuid4


class SystemLog(Base):
    __tablename__ = "system_log"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True, unique=True)
    user_id = Column(ForeignKey("users.id"), nullable=True)
    log_category = Column(String(32), nullable=False)
    comment = Column(String(512), nullable=False)
    time_added = Column(DateTime, default=func.now())


class DBUser(Base):
    __tablename__ = "users"
    id = Column(
        UUID, primary_key=True, index=True, unique=True, nullable=False, default=uuid4
    )
    username = Column(String(32), unique=True, nullable=False, index=True)
    hashed_password = Column(String(64))
    first_name = Column(String(32))
    last_name = Column(String(32))
    account_created = Column(DateTime, default=func.now())
    locked = Column(Boolean, default=False)
    account_updated = Column(DateTime, onupdate=func.now(), default=func.now())


class TimeLog(Base):
    __tablename__ = "time_log"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True, unique=True)
    user_id = Column(ForeignKey("users.id"), nullable=False)
    event_added = Column(DateTime, default=func.now())
    date = Column(DATE, default=datetime.now().date())
    short_desc = Column(String(64))
    comment = Column(String(1024))
