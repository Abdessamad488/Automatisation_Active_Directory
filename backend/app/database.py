"""
Database Configuration and Connection Management
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from neo4j import AsyncGraphDatabase, GraphDatabase
from redis import Redis
from typing import AsyncGenerator, Generator

from app.config import settings


# SQLAlchemy setup
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Neo4j setup (synchronous for simplicity)
neo4j_driver = GraphDatabase.driver(
    settings.NEO4J_URI,
    auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD)
)


def get_neo4j():
    """Get Neo4j driver"""
    return neo4j_driver


# Redis setup
redis_client = Redis.from_url(
    settings.REDIS_URL,
    decode_responses=True
)


def get_redis():
    """Get Redis client"""
    return redis_client


async def init_db():
    """Initialize database connections"""
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    # Test Neo4j connection
    with neo4j_driver.session() as session:
        session.run("RETURN 1")
    
    # Test Redis connection
    redis_client.ping()


async def close_db():
    """Close database connections"""
    engine.dispose()
    neo4j_driver.close()
    redis_client.close()