import pandas as pd


ALLOWED_INDICATOR_TYPES = {
    "IP ADDRESS",
    "DOMAIN",
    "URL",
    "FILE HASH",
    "EMAIL/SENDER DOMAIN",
    "CVE ID"
}


ALLOWED_CATEGORIES = {
    "PHISHING",
    "MALWARE",
    "RANSOMWARE",
    "CREDENTIAL THREATS",
    "WEB THREATS",
    "NETWORK THREATS",
    "VULNERABILITY EXPOSURE",
    "SOCIAL ENGINEERING",
    "DATA EXPOSURE",
    "ACCOUNT SECURITY"
}


ALLOWED_SEVERITIES = {
    "INFORMATIONAL",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
}


ALLOWED_STATUSES = {
    "OBSERVATION",
    "INDICATOR",
    "ALERT",
    "THREAT",
    "INCIDENT"
}


REQUIRED_COLUMNS = {
    "threat_id",
    "observed_date",
    "indicator",
    "indicator_type",
    "threat_category",
    "severity",
    "confidence",
    "status",
    "source",
    "description",
    "mitre_technique",
    "recommendation"
}


def validate_threat_data(df):
    """
    Validate the threat intelligence dataset.

    Returns:
        list: Validation errors.
    """

    errors = []

    # Check required columns
    missing_columns = REQUIRED_COLUMNS - set(df.columns)

    if missing_columns:
        errors.append(
            f"Missing required columns: {', '.join(sorted(missing_columns))}"
        )

    # Stop further validation if required columns are missing
    if missing_columns:
        return errors

    # Check missing values
    for column in REQUIRED_COLUMNS:
        missing_count = df[column].isna().sum()

        if missing_count > 0:
            errors.append(
                f"Column '{column}' contains {missing_count} missing value(s)."
            )

    # Check duplicate threat IDs
    duplicate_ids = df[df["threat_id"].duplicated()]["threat_id"].tolist()

    if duplicate_ids:
        errors.append(
            f"Duplicate threat IDs found: {', '.join(duplicate_ids)}"
        )

    # Check indicator types
    invalid_indicator_types = set(df["indicator_type"].dropna()) - ALLOWED_INDICATOR_TYPES

    if invalid_indicator_types:
        errors.append(
            "Invalid indicator type(s): "
            + ", ".join(sorted(invalid_indicator_types))
        )

    # Check threat categories
    invalid_categories = set(df["threat_category"].dropna()) - ALLOWED_CATEGORIES

    if invalid_categories:
        errors.append(
            "Invalid threat category/categoryies: "
            + ", ".join(sorted(invalid_categories))
        )

    # Check severity
    invalid_severities = set(df["severity"].dropna()) - ALLOWED_SEVERITIES

    if invalid_severities:
        errors.append(
            "Invalid severity value(s): "
            + ", ".join(sorted(invalid_severities))
        )

    # Check status
    invalid_statuses = set(df["status"].dropna()) - ALLOWED_STATUSES

    if invalid_statuses:
        errors.append(
            "Invalid status value(s): "
            + ", ".join(sorted(invalid_statuses))
        )

    return errors