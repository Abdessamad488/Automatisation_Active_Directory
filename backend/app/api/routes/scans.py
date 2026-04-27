"""
Scan Management Routes
"""
from typing import List
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import Scan
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanResponse, ScanUpdate
from app.api.routes.auth import get_current_user
from app.core.pentest.pipeline_orchestrator import PentestPipeline, PipelineConfig

router = APIRouter()


@router.post("/", response_model=ScanResponse)
async def create_scan(
    scan: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create new pentest scan"""
    db_scan = Scan(
        name=scan.name,
        target_domain=scan.target_domain,
        target_ips=scan.target_ips,
        status="pending",
        created_by=current_user.id,
        settings=scan.settings
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    
    # Start scan in background using new 7-phase pipeline
    background_tasks.add_task(run_pipeline, db_scan.id, scan.target_domain, scan.target_ips)
    
    return db_scan


async def run_pipeline(scan_id: UUID, target_domain: str, target_ips: List[str]):
    """Execute pentest using 7-phase pipeline"""
    config = PipelineConfig(
        domain=target_domain,
        target_ips=target_ips,
        scan_name=f"Scan {scan_id}"
    )
    
    # Pass scan_id to pipeline
    pipeline = PentestPipeline(config, scan_id=scan_id)
    await pipeline.run_full_pipeline()


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all scans"""
    scans = db.query(Scan).offset(skip).limit(limit).all()
    return scans


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get scan details"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete scan"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    db.delete(scan)
    db.commit()
    
    return {"message": "Scan deleted"}


@router.post("/{scan_id}/stop")
async def stop_scan(
    scan_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Stop running scan"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.status != "running":
        raise HTTPException(status_code=400, detail="Scan is not running")
    
    scan.status = "stopped"
    db.commit()
    
    return {"message": "Scan stopped"}