# ---------------------------------------------------------
# Security Alert Engine
# ---------------------------------------------------------

from src.threat_scoring import calculate_threat_risk


ALERT_STATUSES = {
    "ALERT",
    "THREAT",
    "INCIDENT"
}


def is_security_alert(status):
    """
    Determine whether a threat-intelligence record
    represents a security alert state.

    OBSERVATION and INDICATOR are not treated as alerts.
    """

    if not status:
        return False

    return str(status).upper() in ALERT_STATUSES


def create_alert_record(record):
    """
    Create a defensive alert assessment from a
    threat-intelligence record.
    """

    status = str(
        record.get("status", "")
    ).upper()

    severity = str(
        record.get("severity", "INFORMATIONAL")
    ).upper()

    confidence = str(
        record.get("confidence", "LOW")
    ).upper()

    risk_result = calculate_threat_risk(
        severity,
        confidence
    )

    return {
        "alert": is_security_alert(status),
        "alert_status": status,
        "indicator": record.get(
            "indicator",
            ""
        ),
        "indicator_type": record.get(
            "indicator_type",
            ""
        ),
        "threat_category": record.get(
            "threat_category",
            ""
        ),
        "severity": severity,
        "confidence": confidence,
        "risk_score": risk_result["risk_score"],
        "risk_level": risk_result["risk_level"],
        "mitre_technique": record.get(
            "mitre_technique",
            ""
        ),
        "observed_date": record.get(
            "observed_date",
            ""
        ),
        "source": record.get(
            "source",
            ""
        ),
        "description": record.get(
            "description",
            ""
        )
    }


def get_alert_records(df):
    """
    Return only records whose status represents
    ALERT, THREAT, or INCIDENT.
    """

    return df[
        df["status"]
        .astype(str)
        .str.upper()
        .isin(ALERT_STATUSES)
    ].copy()