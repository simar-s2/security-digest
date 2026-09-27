"""Runtime settings, read from the Lambda environment."""

import os
from dataclasses import dataclass, field


def _list(value):
    return [v.strip() for v in value.split(",") if v.strip()]


def _bool(value):
    return value.strip().lower() in ("1", "true", "yes")


@dataclass(frozen=True)
class Settings:
    webhook_param: str = ""
    title: str = "AWS security daily digest"
    severities: list = field(default_factory=lambda: ["CRITICAL", "HIGH"])
    # Inspector CVEs and per-instance patch findings are reported in their own
    # sections; in the main table they would drown the posture findings.
    excluded_products: list = field(default_factory=lambda: ["Inspector", "Systems Manager Patch Manager"])
    max_rows: int = 15
    include_new_cves: bool = True
    include_patch_status: bool = True
    console_region: str = "us-east-1"
    footer: str = ""
    # Real-time alerts skip findings created longer ago than this: Security Hub
    # re-imports existing findings whenever they are updated.
    alert_max_age_hours: int = 24

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        d = cls()
        return cls(
            webhook_param=env.get("WEBHOOK_PARAM", d.webhook_param),
            title=env.get("DIGEST_TITLE", d.title),
            severities=_list(env["SEVERITIES"]) if "SEVERITIES" in env else d.severities,
            excluded_products=(_list(env["EXCLUDED_PRODUCTS"]) if "EXCLUDED_PRODUCTS" in env else d.excluded_products),
            max_rows=int(env.get("MAX_ROWS", d.max_rows)),
            include_new_cves=_bool(env.get("INCLUDE_NEW_CVES", "true")),
            include_patch_status=_bool(env.get("INCLUDE_PATCH_STATUS", "true")),
            console_region=env.get("CONSOLE_REGION", env.get("AWS_REGION", d.console_region)),
            footer=env.get("FOOTER", d.footer),
            alert_max_age_hours=int(env.get("ALERT_MAX_AGE_HOURS", d.alert_max_age_hours)),
        )
