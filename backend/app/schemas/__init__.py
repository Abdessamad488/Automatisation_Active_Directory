"""
Pydantic Schemas for Request/Response Validation
"""
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime


# User Schemas
class UserBase(BaseModel):
    username: str
    email: EmailStr


class UserCreate(UserBase):
    password: str
    role: Optional[str] = "user"


class UserResponse(UserBase):
    id: UUID
    role: str
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


# Scan Schemas
class ScanBase(BaseModel):
    name: str
    target_domain: str
    target_ips: List[str]
    settings: Optional[Dict[str, Any]] = {}


class ScanCreate(ScanBase):
    pass


class ScanUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    progress: Optional[int] = None
    current_phase: Optional[str] = None


class ScanResponse(ScanBase):
    id: UUID
    status: str
    progress: int
    current_phase: Optional[str]
    error_message: Optional[str]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_by: UUID
    
    class Config:
        from_attributes = True


# Finding Schemas
class FindingBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str
    category: str
    status: Optional[str] = "open"
    affected_target: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = {}
    remediation: Optional[str] = None
    references: Optional[List[str]] = []
    cvss_score: Optional[int] = None


class FindingCreate(FindingBase):
    scan_id: UUID


class FindingUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    status: Optional[str] = None
    affected_target: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    remediation: Optional[str] = None
    references: Optional[List[str]] = None
    cvss_score: Optional[int] = None


class FindingResponse(FindingBase):
    id: UUID
    scan_id: UUID
    risk_score: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


# Graph Schemas
class NodeResponse(BaseModel):
    id: str
    type: str
    name: str
    properties: Dict[str, Any]


class EdgeResponse(BaseModel):
    source: str
    target: str
    type: str
    properties: Dict[str, Any] = {}


class GraphResponse(BaseModel):
    nodes: List[NodeResponse]
    edges: List[EdgeResponse]


class AttackPathResponse(BaseModel):
    nodes: List[Dict[str, Any]]
    relationships: List[str]
    length: int


# Chat Schemas
class ChatSessionCreate(BaseModel):
    scan_id: Optional[UUID] = None
    title: Optional[str] = "New Chat"


class ChatSessionResponse(BaseModel):
    id: UUID
    user_id: UUID
    scan_id: Optional[UUID]
    title: Optional[str]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class ChatMessageCreate(BaseModel):
    content: str


class ChatMessageResponse(BaseModel):
    id: UUID
    session_id: UUID
    role: str
    content: str
    created_at: datetime
    
    class Config:
        from_attributes = True


# Report Schemas
class ReportCreate(BaseModel):
    scan_id: UUID
    format: str = "pdf"  # pdf, html, markdown, json
    template: str = "standard"  # standard, executive, detailed


class ReportResponse(BaseModel):
    id: UUID
    scan_id: UUID
    format: str
    template: str
    file_path: str
    created_at: datetime
    created_by: UUID
    
    class Config:
        from_attributes = True