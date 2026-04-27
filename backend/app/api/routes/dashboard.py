"""
Dashboard Statistics Routes
"""
from typing import Optional
from uuid import UUID
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding
from app.api.routes.auth import get_current_user

router = APIRouter()


@router.get("/overview")
async def get_dashboard_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get dashboard overview statistics"""
    
    # Scan statistics
    total_scans = db.query(Scan).count()
    scans_by_status = db.query(
        Scan.status, 
        func.count(Scan.id)
    ).group_by(Scan.status).all()
    
    # Finding statistics
    total_findings = db.query(Finding).count()
    findings_by_severity = db.query(
        Finding.severity,
        func.count(Finding.id)
    ).group_by(Finding.severity).all()
    
    # Recent scans
    recent_scans = db.query(Scan).order_by(
        Scan.created_at.desc()
    ).limit(5).all()
    
    return {
        "scans": {
            "total": total_scans,
            "by_status": {status: count for status, count in scans_by_status}
        },
        "findings": {
            "total": total_findings,
            "by_severity": {severity: count for severity, count in findings_by_severity}
        },
        "recent_scans": [
            {
                "id": str(s.id),
                "name": s.name,
                "target_domain": s.target_domain,
                "status": s.status,
                "created_at": s.created_at.isoformat() if s.created_at else None
            }
            for s in recent_scans
        ]
    }


@router.get("/scan/{scan_id}/summary")
async def get_scan_summary(
    scan_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get detailed scan summary"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": "Scan not found"}
    
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    
    # Calculate risk score
    severity_weights = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 1,
        "info": 0
    }
    
    risk_score = sum(
        severity_weights.get(f.severity, 0) 
        for f in findings 
        if f.status != "false_positive"
    )
    
    # Categorize findings
    by_category = {}
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_status = {"open": 0, "confirmed": 0, "false_positive": 0, "remediated": 0}
    
    for f in findings:
        by_category[f.category] = by_category.get(f.category, 0) + 1
        by_severity[f.severity] += 1
        by_status[f.status] += 1
    
    return {
        "scan": {
            "id": str(scan.id),
            "name": scan.name,
            "target_domain": scan.target_domain,
            "status": scan.status,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None
        },
        "findings": {
            "total": len(findings),
            "by_category": by_category,
            "by_severity": by_severity,
            "by_status": by_status
        },
        "risk_score": risk_score,
        "risk_level": "Critical" if risk_score >= 50 else "High" if risk_score >= 25 else "Medium" if risk_score >= 10 else "Low"
    }


@router.get("/timeline")
async def get_timeline(
    days: int = 30,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get scan activity timeline"""
    from datetime import datetime, timedelta
    
    start_date = datetime.utcnow() - timedelta(days=days)
    
    scans = db.query(Scan).filter(
        Scan.created_at >= start_date
    ).order_by(Scan.created_at).all()
    
    # Group by day
    timeline = {}
    for scan in scans:
        day = scan.created_at.date().isoformat()
        if day not in timeline:
            timeline[day] = {"scans": 0, "findings": 0}
        timeline[day]["scans"] += 1
    
    # Get findings count per day
    findings = db.query(Finding).filter(
        Finding.created_at >= start_date
    ).all()
    
    for finding in findings:
        day = finding.created_at.date().isoformat()
        if day in timeline:
            timeline[day]["findings"] += 1
    
    return [
        {"date": date, **data}
        for date, data in sorted(timeline.items())
    ]