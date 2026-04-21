from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db.models.asset import Asset
from app.services.campus_data_source_service import (
    CampusObservation,
    build_time_window_anchor,
    is_locally_administered_mac,
    normalize_mac_address,
    observations_within_window,
)
from app.services.device_assessment_service import apply_device_assessment_to_asset, build_asset_device_assessment

DEFAULT_ASSOCIATION_WINDOW_SECONDS = 1800


@dataclass(slots=True)
class AssetAssociationDecision:
    asset: Asset | None
    match_reason: str
    confidence: int


def find_asset_for_observation(
    db: Session,
    observation: CampusObservation,
    *,
    window_seconds: int = DEFAULT_ASSOCIATION_WINDOW_SECONDS,
) -> AssetAssociationDecision:
    zone = str(observation.network_zone or "").strip() or None
    vlan = str(observation.network_vlan or "").strip() or None
    hostname = str(observation.hostname or "").strip() or None
    ip = str(observation.ip or "").strip() or None
    mac = normalize_mac_address(observation.mac_address)
    observed_anchor = build_time_window_anchor(observed_at=observation.observed_at, last_auth_time=None, last_seen_at=None)

    if mac:
        stmt = select(Asset).where(Asset.mac_address == mac)
        candidates = db.scalars(stmt).all()
        for candidate in candidates:
            candidate_zone = str(candidate.network_zone or "").strip() or None
            candidate_vlan = str(candidate.network_vlan or "").strip() or None
            candidate_anchor = build_time_window_anchor(
                observed_at=None,
                last_auth_time=candidate.last_auth_time,
                last_seen_at=candidate.last_seen_at,
            )
            zone_match = bool(zone and candidate_zone and zone == candidate_zone)
            vlan_match = bool(vlan and candidate_vlan and vlan == candidate_vlan)
            if zone_match or vlan_match:
                if is_locally_administered_mac(mac):
                    if observations_within_window(observed_anchor, candidate_anchor, window_seconds=window_seconds):
                        return AssetAssociationDecision(candidate, "mac+zone_time_window", 95)
                else:
                    return AssetAssociationDecision(candidate, "mac+zone_or_vlan", 99)

    if ip and zone:
        stmt = select(Asset).where(Asset.ip == ip, Asset.network_zone == zone)
        candidate = db.scalar(stmt)
        if candidate is not None:
            return AssetAssociationDecision(candidate, "ip+zone", 90)

    if hostname and zone:
        stmt = select(Asset).where(Asset.hostname == hostname, Asset.network_zone == zone)
        candidates = db.scalars(stmt).all()
        for candidate in candidates:
            candidate_anchor = build_time_window_anchor(
                observed_at=None,
                last_auth_time=candidate.last_auth_time,
                last_seen_at=candidate.last_seen_at,
            )
            if observations_within_window(observed_anchor, candidate_anchor, window_seconds=window_seconds):
                return AssetAssociationDecision(candidate, "hostname+zone_time_window", 80)

    if ip:
        candidate = db.scalar(select(Asset).where(Asset.ip == ip))
        if candidate is not None:
            candidate_anchor = build_time_window_anchor(
                observed_at=None,
                last_auth_time=candidate.last_auth_time,
                last_seen_at=candidate.last_seen_at,
            )
            if observations_within_window(observed_anchor, candidate_anchor, window_seconds=window_seconds):
                return AssetAssociationDecision(candidate, "ip_time_window", 75)
            if observation.source_type == "active_scan":
                return AssetAssociationDecision(candidate, "ip_active_scan_fallback", 70)

    return AssetAssociationDecision(None, "new_asset", 0)


def apply_observation_to_asset(
    asset: Asset,
    observation: CampusObservation,
    *,
    identity_source: str,
) -> Asset:
    if observation.ip:
        asset.ip = observation.ip
    if observation.hostname:
        asset.hostname = observation.hostname
    if observation.mac_address:
        asset.mac_address = normalize_mac_address(observation.mac_address)
    if observation.vendor:
        asset.vendor = observation.vendor
    if observation.network_zone:
        asset.network_zone = observation.network_zone
    if observation.network_vlan:
        asset.network_vlan = observation.network_vlan
    asset.identity_source = identity_source
    asset.last_auth_time = observation.observed_at
    asset.last_seen_at = max(filter(None, [asset.last_seen_at, observation.observed_at])) if asset.last_seen_at else observation.observed_at
    classify_asset(asset, observation=observation)
    return asset


def upsert_asset_from_observation(
    db: Session,
    observation: CampusObservation,
    *,
    identity_source: str,
    window_seconds: int = DEFAULT_ASSOCIATION_WINDOW_SECONDS,
) -> tuple[Asset, AssetAssociationDecision]:
    decision = find_asset_for_observation(db, observation, window_seconds=window_seconds)
    asset = decision.asset
    if asset is None:
        asset = Asset(ip=observation.ip or "0.0.0.0")
    asset = apply_observation_to_asset(asset, observation, identity_source=identity_source)
    db.add(asset)
    db.flush()
    return asset, decision


def classify_asset(asset: Asset, *, observation: CampusObservation | None = None) -> None:
    observation_ip = str(observation.ip or "").strip() or None if observation else None
    observation_hostname = str(observation.hostname or "").strip() or None if observation else None
    observation_vendor = str(observation.vendor or "").strip() or None if observation else None
    observation_mac = str(observation.mac_address or "").strip() or None if observation else None
    assessment = build_asset_device_assessment(
        asset=asset,
        ip=observation_ip,
        hostname=observation_hostname,
        vendor=observation_vendor,
        mac_address=observation_mac,
        service_names=[observation.device_role] if observation and observation.device_role else [],
        raw_evidence=list(observation.raw_evidence or []) if observation else [],
        explicit_device_role=observation.device_role if observation else None,
        assessment_source="campus_observation",
    )
    apply_device_assessment_to_asset(asset, assessment)
