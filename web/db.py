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
        seed_challenges = [
            {
                "slug": "dojo1-ret2win",
                "title": "Dojo 1: ret2win (Beginner)",
                "description": "Learn the basics of binary exploitation by calling the win() function.",
                "docker_image": "mini-dojo/dojo1-ret2win:latest",
            },
            {
                "slug": "dojo2-ret2win-hidden",
                "title": "Dojo 2: ret2win Hidden (Intermediate)",
                "description": "Find and trigger a hidden win path in a tougher ret2win binary.",
                "docker_image": "mini-dojo/dojo2-ret2win-hidden:latest",
            },
        ]

        for challenge_data in seed_challenges:
            existing = db.query(Challenge).filter_by(slug=challenge_data["slug"]).first()
            if existing:
                print(f"✓ Challenge already exists: {challenge_data['slug']}")
                continue

            challenge = Challenge(**challenge_data)
            db.add(challenge)
            db.commit()
            print(f"✓ Seeded challenge: {challenge_data['slug']}")
    finally:
        db.close()


def get_db():
    """Dependency for FastAPI routes"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
