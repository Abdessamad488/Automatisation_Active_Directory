"""
Database Models
"""
from datetime import datetime
from uuid import uuid4
from sqlalchemy import Column, String, DateTime, Boolean, Integer, Text, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base


class User(Base):
    """User model"""
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default="user")  # admin, user, viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scans = relationship("Scan", back_populates="user")
    chat_sessions = relationship("ChatSession", back_populates="user")
    reports = relationship("Report", back_populates="user")


class Scan(Base):
    """Pentest scan model"""
    __tablename__ = "scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(255), nullable=False)
    target_domain = Column(String(255), nullable=False)
    target_ips = Column(JSON, default=list)  # List of IP addresses
    status = Column(String(50), default="pending")  # pending, running, completed, failed, stopped
    settings = Column(JSON, default=dict)  # Scan configuration
    progress = Column(Integer, default=0)  # Progress percentage
    current_phase = Column(String(100))  # Current scan phase
    error_message = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    # Foreign keys
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    # Relationships
    user = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    chat_sessions = relationship("ChatSession", back_populates="scan")
    reports = relationship("Report", back_populates="scan")


class Finding(Base):
    """Security finding model"""
    __tablename__ = "findings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, index=True)
    
    # Finding details
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    category = Column(String(100), nullable=False)  # kerberoasting, asrep, acl, delegation, etc.
    status = Column(String(20), default="open")  # open, confirmed, false_positive, remediated
    
    # Technical details
    affected_target = Column(String(500))  # Affected host/user
    evidence = Column(JSON, default=dict)  # Raw evidence data
    remediation = Column(Text)
    references = Column(JSON, default=list)  # CVE references, etc.
    
    # Risk scoring
    cvss_score = Column(Integer)  # CVSS v3 score
    risk_score = Column(Integer, default=0)  # Calculated risk score
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="findings")


class ChatSession(Base):
    """AI chat session model"""
    __tablename__ = "chat_sessions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True, index=True)
    title = Column(String(255))
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="chat_sessions")
    scan = relationship("Scan", back_populates="chat_sessions")
    messages = relationship("ChatMessage", back_populates="session", cascade="all, delete-orphan")


class ChatMessage(Base):
    """Chat message model"""
    __tablename__ = "chat_messages"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    session_id = Column(UUID(as_uuid=True), ForeignKey("chat_sessions.id"), nullable=False, index=True)
    
    role = Column(String(20), nullable=False)  # user, assistant
    content = Column(Text, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    session = relationship("ChatSession", back_populates="messages")


class Report(Base):
    """Generated report model"""
    __tablename__ = "reports"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, index=True)
    
    format = Column(String(20), nullable=False)  # pdf, html, markdown, json
    template = Column(String(50), default="standard")  # standard, executive, detailed
    file_path = Column(String(500), nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Foreign keys
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    # Relationships
    scan = relationship("Scan", back_populates="reports")
    user = relationship("User", back_populates="reports")


class AttackPath(Base):
    """Attack path model for Neo4j graph analysis"""
    __tablename__ = "attack_paths"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, index=True)
    
    # Path details
    name = Column(String(255), nullable=False)  # e.g., "Kerberoasting -> DCSync"
    description = Column(Text)
    path_type = Column(String(100))  # kerberoasting, pth, acl, delegation, etc.
    
    # Nodes in the attack path (JSON)
    nodes = Column(JSON, default=list)  # List of node identifiers
    edges = Column(JSON, default=list)  # List of edge relationships
    
    # Risk assessment
    severity = Column(String(20), default="high")  # critical, high, medium, low
    complexity = Column(String(20), default="medium")  # easy, medium, hard
    impact_score = Column(Integer, default=0)
    
    # Status
    status = Column(String(20), default="potential")  # potential, confirmed, exploited
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan")