"""
Findings Management Routes
"""
from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.finding import Finding
from app.models.user import User
from app.schemas.finding import FindingResponse, FindingUpdate
from app.api.routes.auth import get_current_user

router = APIRouter()


@router.get("/", response_model=List[FindingResponse])
async def list_findings(
    scan_id: Optional[UUID] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List findings with filters"""
    query = db.query(Finding)
    
    if scan_id:
        query = query.filter(Finding.scan_id == scan_id)
    if severity:
        query = query.filter(Finding.severity == severity)
    if category:
        query = query.filter(Finding.category == category)
    if status:
        query = query.filter(Finding.status == status)
    
    findings = query.offset(skip).limit(limit).all()
    return findings


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get finding details"""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: UUID,
    finding_update: FindingUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update finding"""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    update_data = finding_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(finding, field, value)
    
    db.commit()
    db.refresh(finding)
    return finding


@router.get("/stats/summary")
async def get_findings_summary(
    scan_id: Optional[UUID] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get findings summary statistics"""
    query = db.query(Finding)
    if scan_id:
        query = query.filter(Finding.scan_id == scan_id)
    
    findings = query.all()
    
    summary = {
        "total": len(findings),
        "by_severity": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        },
        "by_category": {},
        "by_status": {
            "open": 0,
            "confirmed": 0,
            "false_positive": 0,
            "remediated": 0
        }
    }
    
    for finding in findings:
        summary["by_severity"][finding.severity] += 1
        summary["by_category"][finding.category] = \
            summary["by_category"].get(finding.category, 0) + 1
        summary["by_status"][finding.status] += 1
    
    return summary