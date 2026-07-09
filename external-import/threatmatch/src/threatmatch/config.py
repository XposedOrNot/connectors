import os
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import (
    BeforeValidator,
    Field,
    HttpUrl,
    PlainSerializer,
    TypeAdapter,
    field_validator,
    model_validator,
)
from pydantic_core.core_schema import SerializationInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)


class ConfigRetrievalError(Exception):
    """Custom exception for configuration retrieval errors."""


_FILE_PATH = os.path.dirname(os.path.abspath(__file__))


def environ_list_validator(value: str | list[str]) -> list[str]:
    if isinstance(value, str):
        return [string.strip() for string in value.split(",")]
    return value


def pycti_list_serializer(v: list[str], info: SerializationInfo) -> str | list[str]:
    if isinstance(v, list) and info.context and info.context.get("mode") == "pycti":
        return ",".join(v)  # [ "e1", "e2", "e3" ] -> "e1,e2,e3"
    return v


def iso_string_validator(value: str) -> datetime:
    """
    Convert ISO string / timedelta string to a datetime object.

    Example:
        > iso_string_validator("2025-01-01 00:00")
        > datetime.datetime(2025, 1, 1, 0, 0, tzinfo=datetime.timezone.utc)
        > iso_string_validator("P1D")
        > datetime.datetime(2024, 10, 30, 0, 0, tzinfo=datetime.timezone.utc)
    """
    if isinstance(value, str):
        try:
            # Convert presumed ISO string to datetime object
            dt = datetime.fromisoformat(value)
            return (
                dt.astimezone(tz=timezone.utc)
                if dt.tzinfo
                else dt.replace(tzinfo=timezone.utc)
            )
        except ValueError:
            # If not a datetime ISO string, try to parse it as timedelta with pydantic first
            duration = TypeAdapter(timedelta).validate_python(value)
            # Then return a datetime minus the value
            return datetime.now(timezone.utc) - duration
    return value


ListFromString = Annotated[
    list[str],  # Final type
    BeforeValidator(environ_list_validator),
    PlainSerializer(pycti_list_serializer, when_used="json"),
]

DatetimeFromIsoString = Annotated[
    datetime,
    BeforeValidator(iso_string_validator),
    # Replace the default serializer as it uses Z -> +00:00 offset
    PlainSerializer(datetime.isoformat, when_used="json"),
]


class _BaseSettings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", frozen=True)


class _OpenCTIConfig(_BaseSettings):
    url: HttpUrl = Field(description="Base URL of your OpenCTI instance.")
    token: str = Field(
        description="OpenCTI platform token (typically the admin token)."
    )


class _ConnectorConfig(_BaseSettings):
    id: str = Field(description="A UUID v4 to identify the connector in OpenCTI.")

    name: str = Field(default="ThreatMatch", description="The name of the connector.")
    type: str = Field(
        default="EXTERNAL_IMPORT", description="The type of the connector."
    )
    scope: ListFromString = Field(
        default=["threatmatch"], description="The scope of the connector."
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="error",
    )
    duration_period: timedelta = Field(
        default=timedelta(days=1),
        description="Polling frequency as an ISO-8601 duration (e.g., 'P1D').",
    )


class _Threatmatch(_BaseSettings):
    client_id: str = Field(
        description="ThreatMatch OAuth2 client id (Client Credentials)."
    )
    client_secret: str = Field(description="ThreatMatch OAuth2 client secret.")

    url: HttpUrl = Field(
        default=HttpUrl("https://eu.threatmatch.com"),
        description="Base URL of the ThreatMatch API.",
    )
    import_from_date: DatetimeFromIsoString | None = Field(
        default=None,
        description=(
            "Relative ISO-8601 duration (e.g., 'P30D') used to set the first import "
            "window. Applied on the first run only."
        ),
    )
    import_profiles: bool = Field(
        default=True, description="Import the ThreatMatch profiles dataset."
    )
    import_alerts: bool = Field(
        default=True, description="Import the ThreatMatch alerts dataset."
    )
    import_iocs: bool = Field(
        default=True, description="Import the ThreatMatch IOCs dataset."
    )
    tlp_level: Literal["white", "clear", "green", "amber", "amber+strict", "red"] = (
        Field(
            default="amber",
            description="Default TLP marking applied when missing on source objects.",
        )
    )
    threat_actor_as_intrusion_set: bool = Field(
        default=True,
        description="Map ThreatMatch threat-actor objects to STIX intrusion-set.",
    )

    @field_validator("import_from_date", mode="before")
    def _convert_import_from_date_relative_to_utc_datetime(
        cls, value: None | str
    ) -> datetime | str:
        """Allow relative import_from_date values (timedelta)."""
        if value is None:
            return datetime.now(tz=timezone.utc) - timedelta(days=30)
        return value


class ConnectorSettings(_BaseSettings):
    model_config = SettingsConfigDict(
        env_nested_delimiter="_",
        env_nested_max_split=1,
        enable_decoding=False,
        yaml_file=f"{_FILE_PATH}/../config.yml",
    )

    opencti: _OpenCTIConfig = Field(default_factory=lambda: _OpenCTIConfig())
    connector: _ConnectorConfig = Field(default_factory=lambda: _ConnectorConfig())
    threatmatch: _Threatmatch = Field(default_factory=lambda: _Threatmatch())

    def __init__(self) -> None:
        try:
            super().__init__()
        except Exception as e:
            raise ConfigRetrievalError("Invalid OpenCTI configuration.", e) from e

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """
        Customise the sources of settings for the connector.

        This method is called by the Pydantic BaseSettings class to determine the order of sources

        The configuration come in this order either from:
            1. YAML file
            3. Environment variables
            4. Default values
        """
        if Path(settings_cls.model_config["yaml_file"] or "").is_file():  # type: ignore
            return (YamlConfigSettingsSource(settings_cls),)
        return (env_settings,)

    def model_dump_pycti(self) -> dict[str, Any]:
        return self.model_dump(mode="json", context={"mode": "pycti"})

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        if interval := data.get("threatmatch", {}).pop("interval", None):
            warnings.warn(
                "Env var 'THREATMATCH_INTERVAL' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
            )
            data["connector"]["duration_period"] = datetime.timedelta(
                minutes=int(interval)
            )
        return data
