# models.py
import uuid
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(50))
    name = db.Column(db.String(200))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Form(db.Model):
    __tablename__ = 'forms'
    id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = db.Column(db.String(50), db.ForeignKey('events.id'))
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    questions = db.Column(db.JSON)  # Store as JSON
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Response(db.Model):
    __tablename__ = 'responses'
    id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = db.Column(db.String(50), db.ForeignKey('events.id'))
    form_id = db.Column(db.String(50), db.ForeignKey('forms.id'))
    response_id = db.Column(db.String(100), unique=True)
    data = db.Column(db.Text)  # Store response data as JSON string
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.Text)

class VolunteerAccess(db.Model):
    __tablename__ = 'volunteer_access'
    id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = db.Column(db.String(50), db.ForeignKey('events.id'))
    form_id = db.Column(db.String(50), db.ForeignKey('forms.id'))
    code = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.String(100))

class VolunteerSession(db.Model):
    __tablename__ = 'volunteer_sessions'
    id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = db.Column(db.String(50), db.ForeignKey('events.id'))
    form_id = db.Column(db.String(50), db.ForeignKey('forms.id'))
    volunteer_name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime)
    ended_by = db.Column(db.String(50))
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.Text)

class Verification(db.Model):
    __tablename__ = 'verifications'
    id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = db.Column(db.String(50), db.ForeignKey('events.id'))
    form_id = db.Column(db.String(50), db.ForeignKey('forms.id'))
    response_id = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # 'passed', 'declined', 'pending'
    verified_by = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'
    id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = db.Column(db.String(50), db.ForeignKey('events.id'))
    form_id = db.Column(db.String(50), db.ForeignKey('forms.id'))
    sender = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), default='volunteer')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
