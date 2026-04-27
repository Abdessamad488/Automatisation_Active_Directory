"""
PentestAI-AD Main Application
FastAPI application entry point
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager

from app.config import settings
from app.database import init_db, close_db
from app.api.routes import (
    auth, scans, findings, graph, paths, 
    chat, reports, dashboard
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    await init_db()
    yield
    # Shutdown
    await close_db()


app = FastAPI(
    title="PentestAI-AD",
    description="Automated Active Directory Pentesting with AI",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"])
app.include_router(findings.router, prefix="/api/v1/findings", tags=["Findings"])
app.include_router(graph.router, prefix="/api/v1/graph", tags=["Graph"])
app.include_router(paths.router, prefix="/api/v1/paths", tags=["Attack Paths"])
app.include_router(chat.router, prefix="/api/v1/chat", tags=["AI Chat"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["Dashboard"])


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "PentestAI-AD",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}