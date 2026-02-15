from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import hashlib
from passlib.context import CryptContext

Base = declarative_base()
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    workspaces = relationship("Workspace", back_populates="user")
    solves = relationship("Solve", back_populates="user")

    def set_password(self, password: str):
        self.password_hash = password_context.hash(password)

    def check_password(self, password: str) -> bool:
        if self.password_hash.startswith("$2"):
            return password_context.verify(password, self.password_hash)
        return self.password_hash == hashlib.sha256(password.encode()).hexdigest()


class Challenge(Base):
    __tablename__ = "challenges"

    id = Column(Integer, primary_key=True, index=True)
    slug = Column(String, unique=True, index=True, nullable=False)
    title = Column(String, nullable=False)
    description = Column(String, default="")
    docker_image = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    workspaces = relationship("Workspace", back_populates="challenge")
    solves = relationship("Solve", back_populates="challenge")


class Workspace(Base):
    __tablename__ = "workspaces"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    challenge_id = Column(Integer, ForeignKey("challenges.id"), nullable=False)
    container_id = Column(String, nullable=False)
    host_port = Column(Integer, nullable=False)
    flag = Column(String, nullable=False)
    flag_hash = Column(String, nullable=False)
    active = Column(Boolean, default=True)
    started_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="workspaces")
    challenge = relationship("Challenge", back_populates="workspaces")

    def set_flag(self, flag: str):
        self.flag = flag
        self.flag_hash = hashlib.sha256(flag.encode()).hexdigest()

    def check_flag(self, flag: str) -> bool:
        return self.flag_hash == hashlib.sha256(flag.encode()).hexdigest()


class Solve(Base):
    __tablename__ = "solves"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    challenge_id = Column(Integer, ForeignKey("challenges.id"), nullable=False)
    solved_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="solves")
    challenge = relationship("Challenge", back_populates="solves")
