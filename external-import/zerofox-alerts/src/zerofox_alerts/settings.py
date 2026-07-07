"""Configuration settings for the ZeroFox Alerts connector."""

from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector-level configuration for ZeroFox Alerts."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="6dc34623-7346-476b-b105-e7b5c2e8f9c8",
    )
    name: str = Field(
        description="The name of the connector.",
        default="ZeroFox Alerts",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["zerofox-alerts"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=15),
    )


class ZerofoxAlertsConfig(BaseConfigModel):
    """ZeroFox Alerts API configuration."""

    api_base_url: str = Field(
        description="Base URL of the ZeroFox API.",
        default="https://api.zerofox.com",
    )
    api_token: SecretStr = Field(
        description="ZeroFox Personal Access Token (PAT) for authentication.",
    )
    marking: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="TLP marking definition to apply to created objects.",
        default="TLP:AMBER",
    )
    import_start_date: timedelta = Field(
        description="How far back to look on the first import (e.g. 'P30D' for 30 days, 'P6M' for 6 months).",
        default=timedelta(days=30),
    )
    alert_statuses: ListFromString = Field(
        description="Alert statuses to import (comma-separated). E.g. 'open,escalated,investigation_completed'.",
        default=["open", "escalated", "investigation_completed"],
    )
    page_size: int = Field(
        description="Number of alerts to retrieve per API page.",
        default=100,
        ge=1,
        le=100,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Root settings combining OpenCTI, connector, and ZeroFox configurations."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    zerofox_alerts: ZerofoxAlertsConfig = Field(default_factory=ZerofoxAlertsConfig)
