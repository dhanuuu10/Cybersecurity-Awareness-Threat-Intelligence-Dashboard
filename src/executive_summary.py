# =========================================================
# Executive Cybersecurity Summary
# =========================================================


def generate_executive_summary(df):
    """
    Generate a high-level cybersecurity summary
    from the threat intelligence dataset.
    """

    total_records = len(df)

    unique_indicators = (
        df["indicator"]
        .nunique()
    )

    high_critical_count = len(
        df[
            df["severity"]
            .astype(str)
            .str.upper()
            .isin(
                [
                    "HIGH",
                    "CRITICAL"
                ]
            )
        ]
    )

    alert_count = len(
        df[
            df["status"]
            .astype(str)
            .str.upper()
            == "ALERT"
        ]
    )

    threat_count = len(
        df[
            df["status"]
            .astype(str)
            .str.upper()
            == "THREAT"
        ]
    )

    incident_count = len(
        df[
            df["status"]
            .astype(str)
            .str.upper()
            == "INCIDENT"
        ]
    )


    # -----------------------------------------------------
    # MOST COMMON THREAT CATEGORY
    # -----------------------------------------------------

    if not df["threat_category"].dropna().empty:

        most_common_category = (
            df["threat_category"]
            .astype(str)
            .value_counts()
            .idxmax()
        )

    else:

        most_common_category = "Not available"


    # -----------------------------------------------------
    # MOST COMMON INDICATOR TYPE
    # -----------------------------------------------------

    if not df["indicator_type"].dropna().empty:

        most_common_indicator_type = (
            df["indicator_type"]
            .astype(str)
            .value_counts()
            .idxmax()
        )

    else:

        most_common_indicator_type = "Not available"


    # -----------------------------------------------------
    # OVERALL RISK POSTURE
    # -----------------------------------------------------

    if incident_count > 0 or high_critical_count >= 5:

        risk_posture = "HIGH"

    elif threat_count > 0 or high_critical_count > 0:

        risk_posture = "MEDIUM"

    else:

        risk_posture = "LOW"


    # -----------------------------------------------------
    # DEFENSIVE RECOMMENDATIONS
    # -----------------------------------------------------

    recommendations = []


    if high_critical_count > 0:

        recommendations.append(
            "Prioritize investigation of High and Critical severity records."
        )


    if alert_count > 0:

        recommendations.append(
            "Review active security alerts using established SOC procedures."
        )


    if threat_count > 0:

        recommendations.append(
            "Validate threat assessments using relevant security logs and evidence."
        )


    if incident_count > 0:

        recommendations.append(
            "Follow the organization's incident-response process for incident records."
        )


    recommendations.append(
        "Continue cybersecurity awareness training for users."
    )


    recommendations.append(
        "Maintain strong authentication and access-control practices."
    )


    recommendations.append(
        "Keep systems and applications updated with appropriate security patches."
    )


    return {
        "total_records": total_records,
        "unique_indicators": unique_indicators,
        "high_critical_count": high_critical_count,
        "alert_count": alert_count,
        "threat_count": threat_count,
        "incident_count": incident_count,
        "most_common_category": most_common_category,
        "most_common_indicator_type": most_common_indicator_type,
        "risk_posture": risk_posture,
        "recommendations": recommendations
    }