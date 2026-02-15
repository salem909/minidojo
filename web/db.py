from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Challenge
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://dojo:dojo_pass@db:5432/dojo")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Initialize database tables and seed challenges"""
    Base.metadata.create_all(bind=engine)
    
    # Seed challenges
    db = SessionLocal()
    try:
        # Check if challenges already exist
        existing = db.query(Challenge).filter_by(slug="dojo1-ret2win").first()
        if not existing:
            challenge = Challenge(
                slug="dojo1-ret2win",
                title="Dojo 1: ret2win (Beginner)",
                description="Learn the basics of binary exploitation by calling the win() function.",
                docker_image="mini-dojo/dojo1-ret2win:latest"
            )
            db.add(challenge)
            db.commit()
            print("✓ Seeded challenge: dojo1-ret2win")
        else:
            print("✓ Challenge already exists: dojo1-ret2win")
    finally:
        db.close()


def get_db():
    """Dependency for FastAPI routes"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
