"""
Database Schemas for Wedding Website

Each Pydantic model represents a collection in MongoDB.
Collection name is the lowercase of the class name.
"""
from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime


class User(BaseModel):
    email: EmailStr = Field(..., description="Unique email address")
    role: str = Field("guest", description="Role: admin or guest")
    name: Optional[str] = Field(None, description="Display name")
    blocked: bool = Field(False, description="Whether the user is blocked")


class RSVP(BaseModel):
    email: EmailStr = Field(..., description="Guest email for lookup")
    name: str = Field(..., description="Guest name")
    attending: bool = Field(..., description="Will attend")
    guests: int = Field(0, ge=0, le=10, description="Additional guests count")
    dietary: Optional[str] = Field(None, description="Dietary needs")
    message: Optional[str] = Field(None, description="Optional message")


class Gift(BaseModel):
    title: str = Field(..., description="Gift name")
    description: Optional[str] = Field(None, description="Gift description")
    link: Optional[str] = Field(None, description="Optional link to product")
    claimed_by: Optional[str] = Field(None, description="Name of person who claimed")
    claim_note: Optional[str] = Field(None, description="Optional note from claimer")
    claimed_at: Optional[datetime] = Field(None, description="Claim timestamp")


class GiftClaim(BaseModel):
    gift_id: str = Field(..., description="Gift document id")
    name: str = Field(..., description="Claimer name")
    note: Optional[str] = Field(None, description="Optional note")
    action: str = Field("claim", description="claim or unclaim")


class Photo(BaseModel):
    url: str = Field(..., description="Image URL")
    caption: Optional[str] = Field(None, description="Caption")
    uploaded_by: Optional[str] = Field(None, description="Uploader name or email")


class Message(BaseModel):
    name: str = Field(..., description="Sender name")
    text: str = Field(..., min_length=1, max_length=500, description="Message text")
    public: bool = Field(True, description="Whether message is public")


class TimelineEvent(BaseModel):
    title: str = Field(..., description="Event title")
    time: str = Field(..., description="Time, e.g., 12:00")
    location: Optional[str] = Field(None, description="Location")
    description: Optional[str] = Field(None, description="Description")
    order: int = Field(0, description="Sort order")


class GuestGroup(BaseModel):
    name: str = Field(..., description="Group name")
    members: List[str] = Field(default_factory=list, description="Emails of members")
