# ---------------------------------------------------------
# Threat Severity & Confidence Scoring
# ---------------------------------------------------------


SEVERITY_SCORES = {
    "INFORMATIONAL": 10,
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
    "CRITICAL": 100
}


CONFIDENCE_SCORES = {
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75
}


def calculate_risk_score(severity, confidence):
    """
    Calculate a risk score using severity and confidence.

    The score is an assessment value and does not confirm
    that an attack or incident occurred.
    """

    severity_score = SEVERITY_SCORES.get(
        severity.upper(),
        0
    )

    confidence_score = CONFIDENCE_SCORES.get(
        confidence.upper(),
        0
    )

    risk_score = (
        (severity_score * 0.70)
        + (confidence_score * 0.30)
    )

    return round(risk_score)


def classify_risk_level(risk_score):
    """
    Convert the numerical risk score into a risk level.
    """

    if risk_score >= 90:
        return "CRITICAL"

    elif risk_score >= 70:
        return "HIGH"

    elif risk_score >= 40:
        return "MEDIUM"

    elif risk_score >= 20:
        return "LOW"

    else:
        return "INFORMATIONAL"


def calculate_threat_risk(severity, confidence):
    """
    Calculate complete threat-risk assessment.
    """

    risk_score = calculate_risk_score(
        severity,
        confidence
    )

    risk_level = classify_risk_level(
        risk_score
    )

    return {
        "severity": severity.upper(),
        "confidence": confidence.upper(),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "assessment": (
            "Risk score represents a defensive assessment "
            "based on severity and confidence. It does not "
            "confirm that an attack or security incident occurred."
        )
    }