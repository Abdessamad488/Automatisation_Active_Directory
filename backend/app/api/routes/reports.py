"""
Report Generation Routes
"""
from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.scan import Scan
from app.schemas.report import ReportCreate, ReportResponse
from app.api.routes.auth import get_current_user
from app.core.reporting.generator import ReportGenerator

router = APIRouter()
report_generator = ReportGenerator()


@router.post("/", response_model=ReportResponse)
async def create_report(
    report: ReportCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generate new report"""
    # Verify scan exists
    scan = db.query(Scan).filter(Scan.id == report.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Generate report
    report_path = await report_generator.generate(
        scan_id=report.scan_id,
        format=report.format,
        template=report.template
    )
    
    # Save to database
    from app.models.report import Report
    db_report = Report(
        scan_id=report.scan_id,
        format=report.format,
        template=report.template,
        file_path=report_path,
        created_by=current_user.id
    )
    db.add(db_report)
    db.commit()
    db.refresh(db_report)
    
    return db_report


@router.get("/", response_model=List[ReportResponse])
async def list_reports(
    scan_id: Optional[UUID] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List reports"""
    from app.models.report import Report
    query = db.query(Report)
    
    if scan_id:
        query = query.filter(Report.scan_id == scan_id)
    
    return query.all()


@router.get("/{report_id}/download")
async def download_report(
    report_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Download report file"""
    from app.models.report import Report
    report = db.query(Report).filter(Report.id == report_id).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return FileResponse(
        report.file_path,
        filename=f"pentest_report_{report.scan_id}.{report.format}",
        media_type="application/octet-stream"
    )


@router.get("/{report_id}/preview")
async def preview_report(
    report_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Preview report content"""
    from app.models.report import Report
    report = db.query(Report).filter(Report.id == report_id).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Read and return content
    with open(report.file_path, 'r') as f:
        content = f.read()
    
    return {"content": content}