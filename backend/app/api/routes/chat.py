"""
AI Chat Routes
"""
from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.chat import ChatMessage, ChatSession
from app.schemas.chat import (
    ChatMessageCreate, ChatMessageResponse,
    ChatSessionCreate, ChatSessionResponse
)
from app.api.routes.auth import get_current_user
from app.core.ai.engine import AIEngine

router = APIRouter()
ai_engine = AIEngine()


@router.post("/sessions", response_model=ChatSessionResponse)
async def create_chat_session(
    session: ChatSessionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create new chat session"""
    db_session = ChatSession(
        user_id=current_user.id,
        scan_id=session.scan_id,
        title=session.title
    )
    db.add(db_session)
    db.commit()
    db.refresh(db_session)
    return db_session


@router.get("/sessions", response_model=List[ChatSessionResponse])
async def list_chat_sessions(
    scan_id: Optional[UUID] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List chat sessions"""
    query = db.query(ChatSession).filter(ChatSession.user_id == current_user.id)
    if scan_id:
        query = query.filter(ChatSession.scan_id == scan_id)
    return query.all()


@router.get("/sessions/{session_id}/messages", response_model=List[ChatMessageResponse])
async def get_chat_messages(
    session_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get chat messages for a session"""
    messages = db.query(ChatMessage).filter(
        ChatMessage.session_id == session_id
    ).order_by(ChatMessage.created_at).all()
    return messages


@router.post("/sessions/{session_id}/messages", response_model=ChatMessageResponse)
async def send_message(
    session_id: UUID,
    message: ChatMessageCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Send message to AI and get response"""
    # Get session
    session = db.query(ChatSession).filter(
        ChatSession.id == session_id,
        ChatSession.user_id == current_user.id
    ).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Save user message
    db_message = ChatMessage(
        session_id=session_id,
        role="user",
        content=message.content
    )
    db.add(db_message)
    db.commit()
    
    # Get AI response
    response = await ai_engine.chat(
        message=message.content,
        scan_id=session.scan_id,
        history=await get_chat_history(db, session_id)
    )
    
    # Save AI response
    ai_message = ChatMessage(
        session_id=session_id,
        role="assistant",
        content=response
    )
    db.add(ai_message)
    db.commit()
    db.refresh(ai_message)
    
    return ai_message


async def get_chat_history(db: Session, session_id: UUID) -> List[dict]:
    """Get chat history for context"""
    messages = db.query(ChatMessage).filter(
        ChatMessage.session_id == session_id
    ).order_by(ChatMessage.created_at).all()
    
    return [{"role": m.role, "content": m.content} for m in messages]