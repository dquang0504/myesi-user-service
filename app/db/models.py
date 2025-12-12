import uuid
from sqlalchemy import (
    TIMESTAMP,
    UUID,
    BigInteger,
    Boolean,
    Column,
    ForeignKey,
    Integer,
    String,
    DateTime,
    Text,
    func,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import JSONB


Base = declarative_base()


class OwnerAccount(Base):
    __tablename__ = "owner_accounts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="owner", nullable=False)
    is_active = Column(Boolean, default=True)
    two_factor_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(100), default="developer", nullable=False)
    is_active = Column(Boolean, default=True)
    organization_id = Column(Integer, nullable=False)
    two_factor_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    last_login_ip = Column(String(64), nullable=True)
    last_login_user_agent = Column(Text, nullable=True)
    github_token = Column(String, nullable=True)


class UserTwoFactor(Base):
    __tablename__ = "user_two_factors"

    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    secret = Column(String(255), nullable=False)
    is_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now())


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)
    subscription_id = Column(BigInteger, nullable=True)
    owner_id = Column(Integer, ForeignKey("owner_accounts.id"), nullable=False)
    require_two_factor = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class OrganizationSettings(Base):
    __tablename__ = "organization_settings"

    organization_id = Column(Integer, ForeignKey("organizations.id"), primary_key=True)
    admin_email = Column(String(255), nullable=True)
    support_email = Column(String(255), nullable=True)
    require_two_factor = Column(Boolean, default=False)
    password_expiry = Column(Boolean, default=True)
    session_timeout = Column(Boolean, default=True)
    ip_whitelisting = Column(Boolean, default=False)
    email_notifications = Column(Boolean, default=True)
    vulnerability_alerts = Column(Boolean, default=True)
    weekly_reports = Column(Boolean, default=True)
    user_activity_alerts = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now())


# SBOM table
class SBOM(Base):
    __tablename__ = "sboms"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_name = Column(String(255), nullable=False)
    source = Column(String(50), nullable=False)
    sbom = Column(JSONB, nullable=False)
    summary = Column(JSONB)
    object_url = Column(String(1024))
    created_at = Column(
        TIMESTAMP(timezone=True), server_default="now()", nullable=False
    )
    updated_at = Column(TIMESTAMP(timezone=True), server_default="now()")


# Vulnerabilities table
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    sbom_id = Column(UUID(as_uuid=True), ForeignKey("sboms.id"), nullable=False)
    project_name = Column(Text)
    component_name = Column(Text, nullable=False)
    component_version = Column(Text, nullable=False)
    vuln_id = Column(Text, nullable=True)  # optional
    severity = Column(Text)
    fix_available = Column(Boolean, default=False)
    fixed_version = Column(Text)
    osv_metadata = Column(JSONB)
    cvss_vector = Column(String(255))
    sbom_component_count = Column(Integer, default=0)
    sbom_hash = Column(Text)
    created_at = Column(TIMESTAMP(timezone=True), server_default="now()")
    updated_at = Column(TIMESTAMP(timezone=True), server_default="now()")
