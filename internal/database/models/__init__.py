"""All database models - import here to register with SQLAlchemy."""

from internal.database.models.users import User, Organization, UserOrganization
from internal.database.models.targets import Target, Subdomain, LiveHost, Port, Technology, Screenshot
from internal.database.models.scans import ScanJob, ScanResult, Finding, Vulnerability
from internal.database.models.reporting import Report, ActivityLog, ScanSchedule
from internal.database.models.v2_features import (
    JSEndpoint,
    JSSecret,
    DNSRecord,
    APIDiscovery,
    CloudExposure,
)

__all__ = [
    "User",
    "Organization",
    "UserOrganization",
    "Target",
    "Subdomain",
    "LiveHost",
    "Port",
    "Technology",
    "Screenshot",
    "ScanJob",
    "ScanResult",
    "Finding",
    "Vulnerability",
    "Report",
    "ActivityLog",
    "ScanSchedule",
    "JSEndpoint",
    "JSSecret",
    "DNSRecord",
    "APIDiscovery",
    "CloudExposure",
]
