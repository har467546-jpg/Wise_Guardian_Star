from uuid import uuid4

from sqlalchemy import Boolean, Enum, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.enums import RiskSeverity


class RiskRule(Base):
    __tablename__ = "risk_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    service_name: Mapped[str] = mapped_column(String(128), index=True)
    version_constraint: Mapped[str] = mapped_column(String(128))
    severity: Mapped[RiskSeverity] = mapped_column(Enum(RiskSeverity))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(String)
    reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    findings = relationship("RiskFinding", back_populates="rule")
