# =========================================================
# Cybersecurity Awareness & Threat Intelligence Dashboard
# =========================================================

import streamlit as st
import pandas as pd

from src.data_loader import load_threat_data
from src.ioc_analyzer import analyze_ioc
from src.threat_scoring import calculate_threat_risk
from src.mitre_mapping import get_mitre_mapping
from src.alert_engine import create_alert_record, get_alert_records
from src.awareness_content import (
    get_awareness_topics,
    get_awareness_topic
)
from src.quiz_data import (
    get_quiz_questions,
    calculate_quiz_score
)
from src.executive_summary import generate_executive_summary

from src.vulnerability_awareness import (
    get_vulnerabilities,
    search_vulnerabilities,
    get_vulnerability_by_cve,
    get_vulnerability_statistics
)


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="Cybersecurity Awareness & Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide"
)


# =========================================================
# CUSTOM CSS
# =========================================================

st.markdown(
    """
    <style>

    .main {
        background-color: #f5f7fb;
    }

    .dashboard-title {
        font-size: 36px;
        font-weight: bold;
        text-align: center;
        margin-bottom: 10px;
    }

    .dashboard-subtitle {
        text-align: center;
        color: #666666;
        margin-bottom: 30px;
    }

    .section-title {
        font-size: 26px;
        font-weight: bold;
        margin-top: 30px;
        margin-bottom: 15px;
    }

    .info-box {
        padding: 15px;
        border-radius: 10px;
        background-color: #ffffff;
        border: 1px solid #dddddd;
        margin-bottom: 15px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# =========================================================
# DASHBOARD HEADER
# =========================================================

st.markdown(
    '<div class="dashboard-title">'
    '🛡️ Cybersecurity Awareness & Threat Intelligence Dashboard'
    '</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="dashboard-subtitle">'
    'Defensive Security Monitoring, Threat Intelligence, '
    'IOC Analysis & Security Awareness'
    '</div>',
    unsafe_allow_html=True
)


# =========================================================
# LOAD THREAT INTELLIGENCE DATA
# =========================================================

df = load_threat_data()

if df.empty:

    st.error(
        "Threat intelligence dataset could not be loaded."
    )

    st.stop()


# =========================================================
# DATA PREPARATION
# =========================================================

if "observed_date" in df.columns:

    df["observed_date"] = pd.to_datetime(
        df["observed_date"],
        errors="coerce"
    )


# =========================================================
# ADVANCED THREAT FILTERING
# =========================================================

st.markdown(
    '<div class="section-title">'
    '🔎 Advanced Threat Filtering'
    '</div>',
    unsafe_allow_html=True
)

st.info(
    "Use the filters below to narrow the threat intelligence "
    "records displayed throughout the dashboard."
)


filter_col1, filter_col2, filter_col3 = st.columns(3)


# =========================================================
# SEVERITY FILTER
# =========================================================

with filter_col1:

    severity_options = sorted(
        df["severity"]
        .dropna()
        .astype(str)
        .str.upper()
        .unique()
        .tolist()
    )

    severity_filter = st.selectbox(
        "Severity",
        ["All"] + severity_options,
        index=0,
        key="severity_filter"
    )


# =========================================================
# THREAT CATEGORY FILTER
# =========================================================

with filter_col2:

    category_options = sorted(
        df["threat_category"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    category_filter = st.selectbox(
        "Threat Category",
        ["All"] + category_options,
        index=0,
        key="category_filter"
    )


# =========================================================
# INDICATOR TYPE FILTER
# =========================================================

with filter_col3:

    indicator_type_options = sorted(
        df["indicator_type"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    indicator_type_filter = st.selectbox(
        "Indicator Type",
        ["All"] + indicator_type_options,
        index=0,
        key="indicator_type_filter"
    )


filter_col4, filter_col5 = st.columns(2)


# =========================================================
# SECURITY STATUS FILTER
# =========================================================

with filter_col4:

    status_options = sorted(
        df["status"]
        .dropna()
        .astype(str)
        .str.upper()
        .unique()
        .tolist()
    )

    status_filter = st.selectbox(
        "Security Status",
        ["All"] + status_options,
        index=0,
        key="status_filter"
    )


# =========================================================
# CONFIDENCE FILTER
# =========================================================

with filter_col5:

    confidence_options = sorted(
        df["confidence"]
        .dropna()
        .astype(str)
        .str.upper()
        .unique()
        .tolist()
    )

    confidence_filter = st.selectbox(
        "Confidence",
        ["All"] + confidence_options,
        index=0,
        key="confidence_filter"
    )


# =========================================================
# APPLY FILTERS
# =========================================================

filtered_df = df.copy()


if severity_filter != "All":

    filtered_df = filtered_df[
        filtered_df["severity"]
        .astype(str)
        .str.upper()
        == severity_filter
    ]


if category_filter != "All":

    filtered_df = filtered_df[
        filtered_df["threat_category"]
        .astype(str)
        == category_filter
    ]


if indicator_type_filter != "All":

    filtered_df = filtered_df[
        filtered_df["indicator_type"]
        .astype(str)
        == indicator_type_filter
    ]


if status_filter != "All":

    filtered_df = filtered_df[
        filtered_df["status"]
        .astype(str)
        .str.upper()
        == status_filter
    ]


if confidence_filter != "All":

    filtered_df = filtered_df[
        filtered_df["confidence"]
        .astype(str)
        .str.upper()
        == confidence_filter
    ]


# =========================================================
# FILTER RESULT
# =========================================================

st.success(
    f"Showing {len(filtered_df)} filtered records "
    f"out of {len(df)} total records."
)


with st.expander(
    "📋 View Filtered Threat Records"
):

    st.dataframe(
        filtered_df,
        use_container_width=True
    )


# =========================================================
# EXECUTIVE DASHBOARD
# =========================================================

st.markdown(
    '<div class="section-title">'
    '📊 Executive Dashboard'
    '</div>',
    unsafe_allow_html=True
)


total_records = len(filtered_df)

unique_indicators = (
    filtered_df["indicator"]
    .nunique()
)


high_critical = len(
    filtered_df[
        filtered_df["severity"]
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


alerts = len(
    filtered_df[
        filtered_df["status"]
        .astype(str)
        .str.upper()
        == "ALERT"
    ]
)


threats = len(
    filtered_df[
        filtered_df["status"]
        .astype(str)
        .str.upper()
        == "THREAT"
    ]
)


incidents = len(
    filtered_df[
        filtered_df["status"]
        .astype(str)
        .str.upper()
        == "INCIDENT"
    ]
)


metric1, metric2, metric3, metric4, metric5 = st.columns(5)


with metric1:

    st.metric(
        "Threat Records",
        total_records
    )


with metric2:

    st.metric(
        "Unique Indicators",
        unique_indicators
    )


with metric3:

    st.metric(
        "High/Critical",
        high_critical
    )


with metric4:

    st.metric(
        "Alerts",
        alerts
    )


with metric5:

    st.metric(
        "Incidents",
        incidents
    )


# =========================================================
# SECURITY ALERT SUMMARY
# =========================================================

st.markdown(
    '<div class="section-title">'
    '🚨 Security Alert Summary'
    '</div>',
    unsafe_allow_html=True
)


alert_df = get_alert_records(
    filtered_df
)


if alert_df.empty:

    st.info(
        "No ALERT, THREAT, or INCIDENT records "
        "match the current filters."
    )

else:

    st.dataframe(
        alert_df,
        use_container_width=True
    )


# =========================================================
# THREAT CATEGORY ANALYSIS
# =========================================================

st.markdown(
    '<div class="section-title">'
    '🎯 Threat Category Analysis'
    '</div>',
    unsafe_allow_html=True
)


if not filtered_df.empty:

    category_counts = (
        filtered_df["threat_category"]
        .value_counts()
    )

    st.bar_chart(
        category_counts
    )

else:

    st.warning(
        "No data available for threat category analysis."
    )


# =========================================================
# THREAT INTELLIGENCE SEARCH
# =========================================================

st.markdown(
    '<div class="section-title">'
    '🔍 Threat Intelligence Search'
    '</div>',
    unsafe_allow_html=True
)


search_term = st.text_input(
    "Search indicator, category, description, source, or MITRE technique"
)


if search_term:

    search_text = search_term.lower()

    search_mask = (
        filtered_df.astype(str)
        .apply(
            lambda column:
            column.str.lower().str.contains(
                search_text,
                na=False
            )
        )
        .any(axis=1)
    )

    search_results = filtered_df[
        search_mask
    ]

    st.write(
        f"Search results: {len(search_results)}"
    )

    if not search_results.empty:

        st.dataframe(
            search_results,
            use_container_width=True
        )

    else:

        st.warning(
            "No matching threat intelligence records found."
        )


# =========================================================
# THREAT TREND ANALYSIS
# =========================================================

st.markdown(
    '<div class="section-title">'
    '📈 Threat Trend Analysis'
    '</div>',
    unsafe_allow_html=True
)


if (
    not filtered_df.empty
    and "observed_date" in filtered_df.columns
):

    trend_df = (
        filtered_df
        .dropna(subset=["observed_date"])
        .copy()
    )

    if not trend_df.empty:

        trend_data = (
            trend_df
            .groupby(
                trend_df["observed_date"].dt.date
            )
            .size()
        )

        st.line_chart(
            trend_data
        )

    else:

        st.info(
            "Not enough date information for trend analysis."
        )

else:

    st.info(
        "No data available for trend analysis."
    )


# =========================================================
# SEVERITY DISTRIBUTION
# =========================================================

st.markdown(
    '<div class="section-title">'
    '⚠️ Severity Distribution'
    '</div>',
    unsafe_allow_html=True
)


if not filtered_df.empty:

    severity_counts = (
        filtered_df["severity"]
        .astype(str)
        .str.upper()
        .value_counts()
    )

    st.bar_chart(
        severity_counts
    )

else:

    st.info(
        "No data available for severity distribution."
    )


# =========================================================
# SECURITY STATUS DISTRIBUTION
# =========================================================

st.markdown(
    '<div class="section-title">'
    '📌 Security Status Distribution'
    '</div>',
    unsafe_allow_html=True
)


if not filtered_df.empty:

    status_counts = (
        filtered_df["status"]
        .astype(str)
        .str.upper()
        .value_counts()
    )

    st.bar_chart(
        status_counts
    )

else:

    st.info(
        "No data available for security status distribution."
    )


# =========================================================
# SOC ALERT INVESTIGATION
# =========================================================

st.markdown(
    '<div class="section-title">'
    '🕵️ SOC Alert Investigation'
    '</div>',
    unsafe_allow_html=True
)


soc_alerts = get_alert_records(
    filtered_df
)


if soc_alerts.empty:

    st.info(
        "No security alerts are available for investigation."
    )

else:

    alert_options = soc_alerts.index.tolist()

    selected_alert_index = st.selectbox(
        "Select an alert record",
        alert_options,
        format_func=lambda x:
        str(
            soc_alerts.loc[x, "indicator"]
        ),
        key="selected_alert_record"
    )

    selected_alert = soc_alerts.loc[
        selected_alert_index
    ]

    alert_assessment = create_alert_record(
        selected_alert.to_dict()
    )

    st.write(
        "### Alert Details"
    )

    detail_col1, detail_col2 = st.columns(2)

    with detail_col1:

        st.write(
            f"**Indicator:** "
            f"{alert_assessment['indicator']}"
        )

        st.write(
            f"**Indicator Type:** "
            f"{alert_assessment['indicator_type']}"
        )

        st.write(
            f"**Threat Category:** "
            f"{alert_assessment['threat_category']}"
        )

        st.write(
            f"**Security Status:** "
            f"{alert_assessment['alert_status']}"
        )

        st.write(
            f"**Severity:** "
            f"{alert_assessment['severity']}"
        )

    with detail_col2:

        st.write(
            f"**Confidence:** "
            f"{alert_assessment['confidence']}"
        )

        st.write(
            f"**Risk Score:** "
            f"{alert_assessment['risk_score']}"
        )

        st.write(
            f"**Risk Level:** "
            f"{alert_assessment['risk_level']}"
        )

        st.write(
            f"**MITRE Technique:** "
            f"{alert_assessment['mitre_technique']}"
        )

        st.write(
            f"**Source:** "
            f"{alert_assessment['source']}"
        )

    st.write(
        f"**Description:** "
        f"{alert_assessment['description']}"
    )


# =========================================================
# MITRE ATT&CK MAPPING
# =========================================================

st.markdown(
    '<div class="section-title">'
    '🎯 MITRE ATT&CK Mapping'
    '</div>',
    unsafe_allow_html=True
)


if not filtered_df.empty:

    mitre_options = sorted(
        filtered_df["mitre_technique"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    if mitre_options:

        selected_mitre = st.selectbox(
            "Select MITRE ATT&CK Technique",
            mitre_options,
            key="main_mitre_technique"
        )

        mitre_result = get_mitre_mapping(
            selected_mitre
        )

        mitre_col1, mitre_col2 = st.columns(2)

        with mitre_col1:

            st.write(
                f"**Technique ID:** "
                f"{selected_mitre}"
            )

            st.write(
                f"**Technique:** "
                f"{mitre_result.get('technique', 'Unknown')}"
            )

        with mitre_col2:

            st.write(
                f"**Tactic:** "
                f"{mitre_result.get('tactic', 'Unknown')}"
            )

        st.write(
            f"**Description:** "
            f"{mitre_result.get('description', '')}"
        )

    else:

        st.info(
            "No MITRE ATT&CK technique is available "
            "for the selected records."
        )

else:

    st.info(
        "No records are available for MITRE mapping."
    )


# =========================================================
# IOC ANALYSIS
# =========================================================

st.markdown(
    '<div class="section-title">'
    '🔬 IOC Analysis'
    '</div>',
    unsafe_allow_html=True
)


st.info(
    "IOC analysis is passive and local. "
    "The dashboard does not connect to or interact "
    "with suspicious infrastructure."
)


ioc_col1, ioc_col2 = st.columns(2)


with ioc_col1:

    ioc_value = st.text_input(
        "Enter an indicator",
        placeholder="Example: 203.0.113.45",
        key="ioc_value"
    )


with ioc_col2:

    ioc_type = st.selectbox(
        "Select Indicator Type",
        [
            "IP ADDRESS",
            "DOMAIN",
            "URL",
            "FILE HASH",
            "EMAIL/SENDER DOMAIN",
            "CVE ID"
        ],
        key="ioc_type"
    )


if st.button(
    "🔎 Analyze IOC",
    key="analyze_ioc_button"
):

    if not ioc_value.strip():

        st.warning(
            "Please enter an indicator."
        )

    else:

        ioc_result = analyze_ioc(
            ioc_value,
            ioc_type
        )

        st.write(
            "### IOC Analysis Result"
        )

        result_col1, result_col2 = st.columns(2)

        with result_col1:

            st.write(
                f"**Indicator:** "
                f"{ioc_result.get('indicator', '')}"
            )

            st.write(
                f"**Type:** "
                f"{ioc_result.get('type', '')}"
            )

            st.write(
                f"**Valid Format:** "
                f"{ioc_result.get('valid_format', False)}"
            )

        with result_col2:

            if "version" in ioc_result:

                st.write(
                    f"**Version:** "
                    f"{ioc_result.get('version', '')}"
                )

            if "is_private" in ioc_result:

                st.write(
                    f"**Private:** "
                    f"{ioc_result.get('is_private', False)}"
                )

            if "is_global" in ioc_result:

                st.write(
                    f"**Global:** "
                    f"{ioc_result.get('is_global', False)}"
                )

        st.write(
            f"**Analysis:** "
            f"{ioc_result.get('analysis', '')}"
        )


# =========================================================
# IOC THREAT RISK SCORING
# =========================================================

st.markdown(
    '<div class="section-title">'
    '📊 IOC Risk Scoring'
    '</div>',
    unsafe_allow_html=True
)


risk_col1, risk_col2 = st.columns(2)


with risk_col1:

    ioc_severity = st.selectbox(
        "IOC Severity",
        [
            "INFORMATIONAL",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        ],
        key="ioc_severity"
    )


with risk_col2:

    ioc_confidence = st.selectbox(
        "IOC Confidence",
        [
            "LOW",
            "MEDIUM",
            "HIGH"
        ],
        key="ioc_confidence"
    )


if st.button(
    "Calculate IOC Risk Score",
    key="calculate_ioc_risk_button"
):

    risk_result = calculate_threat_risk(
        ioc_severity,
        ioc_confidence
    )

    st.success(
        f"Risk Score: "
        f"{risk_result['risk_score']}"
    )

    st.write(
        f"Risk Level: "
        f"**{risk_result['risk_level']}**"
    )


# =========================================================
# IOC MITRE MAPPING
# =========================================================

st.markdown(
    '<div class="section-title">'
    '🧩 IOC MITRE Context'
    '</div>',
    unsafe_allow_html=True
)


ioc_mitre_technique = st.text_input(
    "Enter a MITRE ATT&CK technique ID",
    placeholder="Example: T1566",
    key="ioc_mitre_technique"
)


if st.button(
    "Show MITRE Information",
    key="show_ioc_mitre_button"
):

    if ioc_mitre_technique.strip():

        ioc_mitre_result = get_mitre_mapping(
            ioc_mitre_technique
        )

        st.write(
            f"**Technique:** "
            f"{ioc_mitre_result.get('technique', 'Unknown')}"
        )

        st.write(
            f"**Tactic:** "
            f"{ioc_mitre_result.get('tactic', 'Unknown')}"
        )

        st.write(
            f"**Description:** "
            f"{ioc_mitre_result.get('description', '')}"
        )

    else:

        st.warning(
            "Please enter a MITRE technique ID."
        )


# =========================================================
# VULNERABILITY & CVE AWARENESS
# =========================================================

st.markdown(
    '<div class="section-title">'
    '🛡️ Vulnerability & CVE Awareness'
    '</div>',
    unsafe_allow_html=True
)


st.warning(
    "Educational notice: The vulnerability records in this "
    "section are fictional local examples created for "
    "defensive cybersecurity awareness. They are not "
    "presented as real CVE records."
)


# =========================================================
# VULNERABILITY STATISTICS
# =========================================================

vulnerability_stats = (
    get_vulnerability_statistics()
)


vuln_col1, vuln_col2, vuln_col3, vuln_col4, vuln_col5 = (
    st.columns(5)
)


with vuln_col1:

    st.metric(
        "Total",
        vulnerability_stats["total"]
    )


with vuln_col2:

    st.metric(
        "Critical",
        vulnerability_stats["critical"]
    )


with vuln_col3:

    st.metric(
        "High",
        vulnerability_stats["high"]
    )


with vuln_col4:

    st.metric(
        "Medium",
        vulnerability_stats["medium"]
    )


with vuln_col5:

    st.metric(
        "Low",
        vulnerability_stats["low"]
    )


# =========================================================
# VULNERABILITY SEARCH
# =========================================================

vulnerability_search = st.text_input(
    "🔎 Search CVE ID, severity, component, or description",
    placeholder="Example: CRITICAL or CVE-2024-0001",
    key="vulnerability_search"
)


vulnerability_results = search_vulnerabilities(
    vulnerability_search
)


if vulnerability_results:

    vulnerability_df = pd.DataFrame(
        vulnerability_results
    )

    st.write(
        f"Found {len(vulnerability_results)} "
        f"vulnerability record(s)."
    )

    display_columns = [
        "cve_id",
        "severity",
        "affected_component",
        "description"
    ]

    st.dataframe(
        vulnerability_df[display_columns],
        use_container_width=True
    )

    # =====================================================
    # SELECT VULNERABILITY
    # =====================================================

    selected_cve = st.selectbox(
        "Select a vulnerability record",
        [
            item["cve_id"]
            for item in vulnerability_results
        ],
        key="selected_vulnerability"
    )

    selected_vulnerability = (
        get_vulnerability_by_cve(
            selected_cve
        )
    )

    if selected_vulnerability:

        st.write(
            "### Vulnerability Details"
        )

        detail_col1, detail_col2 = st.columns(2)

        with detail_col1:

            st.write(
                f"**CVE ID:** "
                f"{selected_vulnerability['cve_id']}"
            )

            st.write(
                f"**Severity:** "
                f"{selected_vulnerability['severity']}"
            )

            st.write(
                f"**Affected Component:** "
                f"{selected_vulnerability['affected_component']}"
            )

        with detail_col2:

            st.write(
                "**Assessment Type:** "
                "Educational / Local Dataset"
            )

            st.write(
                "**Data Source:** "
                "Local project dataset"
            )

        st.write(
            f"**Description:** "
            f"{selected_vulnerability['description']}"
        )

        st.write(
            f"**Potential Impact:** "
            f"{selected_vulnerability['impact']}"
        )

        st.write(
            f"**Recommended Defensive Action:** "
            f"{selected_vulnerability['recommendation']}"
        )

else:

    st.info(
        "No vulnerability records match the search."
    )


# =========================================================
# EXECUTIVE CYBERSECURITY SUMMARY
# =========================================================

st.markdown(
    '<div class="section-title">'
    '📋 Executive Cybersecurity Summary'
    '</div>',
    unsafe_allow_html=True
)


executive_summary = (
    generate_executive_summary(
        filtered_df
    )
)


summary_col1, summary_col2, summary_col3 = st.columns(3)


with summary_col1:

    st.metric(
        "Overall Risk Posture",
        executive_summary["risk_posture"]
    )


with summary_col2:

    st.metric(
        "Most Common Category",
        executive_summary["most_common_category"]
    )


with summary_col3:

    st.metric(
        "Most Common Indicator",
        executive_summary["most_common_indicator_type"]
    )


st.write(
    "### Executive Recommendations"
)


for recommendation in (
    executive_summary["recommendations"]
):

    st.write(
        f"• {recommendation}"
    )


# =========================================================
# SECURITY AWARENESS LEARNING CENTER
# =========================================================

st.markdown(
    '<div class="section-title">'
    '📚 Security Awareness Learning Center'
    '</div>',
    unsafe_allow_html=True
)


awareness_topics = (
    get_awareness_topics()
)


selected_topic = st.selectbox(
    "Select an awareness topic",
    awareness_topics,
    key="awareness_topic"
)


topic_content = get_awareness_topic(
    selected_topic
)


if topic_content:

    st.write(
        f"### {selected_topic}"
    )

    if "description" in topic_content:

        st.write(
            topic_content["description"]
        )

    if "warning_signs" in topic_content:

        st.write(
            "#### ⚠️ Warning Signs"
        )

        for warning in topic_content[
            "warning_signs"
        ]:

            st.write(
                f"• {warning}"
            )

    if "best_practices" in topic_content:

        st.write(
            "#### ✅ Best Practices"
        )

        for practice in topic_content[
            "best_practices"
        ]:

            st.write(
                f"• {practice}"
            )


# =========================================================
# SECURITY AWARENESS QUIZ
# =========================================================

st.markdown(
    '<div class="section-title">'
    '📝 Security Awareness Quiz'
    '</div>',
    unsafe_allow_html=True
)


quiz_questions = get_quiz_questions()


if "quiz_submitted" not in st.session_state:

    st.session_state.quiz_submitted = False


if "quiz_result" not in st.session_state:

    st.session_state.quiz_result = None


quiz_answers = {}


for question in quiz_questions:

    question_id = question["id"]

    selected_answer = st.radio(
        question["question"],
        question["options"],
        key=f"quiz_{question_id}"
    )

    quiz_answers[
        question_id
    ] = selected_answer


if st.button(
    "Submit Security Awareness Quiz",
    key="submit_quiz_button"
):

    quiz_result = calculate_quiz_score(
        quiz_answers
    )

    st.session_state.quiz_submitted = True

    st.session_state.quiz_result = quiz_result


# =========================================================
# QUIZ RESULT
# =========================================================

if st.session_state.quiz_submitted:

    quiz_result = (
        st.session_state.quiz_result
    )

    st.success(
        f"Your Awareness Score: "
        f"{quiz_result['score']}/"
        f"{quiz_result['total']}"
    )

    st.write(
        f"### Percentage: "
        f"{quiz_result['percentage']:.1f}%"
    )

    st.write(
        f"### Awareness Level: "
        f"{quiz_result['awareness_level']}"
    )

    # =====================================================
    # FIXED QUIZ REVIEW SECTION
    # =====================================================

    with st.expander(
        "📖 Review Quiz Answers"
    ):

        for result in quiz_result[
            "results"
        ]:

            # Safely retrieve the question text.
            # Supports both possible key names.
            question_text = result.get(
                "question",
                result.get(
                    "question_text",
                    None
                )
            )

            # If the result does not contain the
            # question text, recover it using question_id.
            if not question_text:

                result_question_id = result.get(
                    "question_id",
                    result.get(
                        "id",
                        None
                    )
                )

                for question in quiz_questions:

                    if question.get("id") == result_question_id:

                        question_text = question.get(
                            "question",
                            "Question not available"
                        )

                        break

            if not question_text:

                question_text = (
                    "Question not available"
                )

            selected_answer = result.get(
                "selected_answer",
                "Not answered"
            )

            correct_answer = result.get(
                "correct_answer",
                "Not available"
            )

            is_correct = result.get(
                "is_correct",
                False
            )

            st.write(
                f"**Question:** "
                f"{question_text}"
            )

            st.write(
                f"Your Answer: "
                f"{selected_answer}"
            )

            st.write(
                f"Correct Answer: "
                f"{correct_answer}"
            )

            if is_correct:

                st.success(
                    "Correct"
                )

            else:

                st.error(
                    "Incorrect"
                )

    # =====================================================
    # AWARENESS LEVEL MESSAGE
    # =====================================================

    percentage = (
        quiz_result["percentage"]
    )

    if percentage >= 90:

        st.success(
            "Excellent cybersecurity awareness. "
            "Continue following strong security practices."
        )

    elif percentage >= 75:

        st.info(
            "Good cybersecurity awareness. "
            "Review the questions you missed."
        )

    elif percentage >= 50:

        st.warning(
            "Your awareness level is developing. "
            "Additional security awareness training is recommended."
        )

    else:

        st.error(
            "Your awareness score indicates that "
            "additional cybersecurity training is recommended."
        )


# =========================================================
# FOOTER
# =========================================================

st.markdown(
    """
    <hr>

    <div style="text-align:center; color:#777777;">

    <p>
    🛡️ Cybersecurity Awareness & Threat Intelligence Dashboard
    </p>

    <p>
    Defensive cybersecurity project |
    Local threat intelligence |
    IOC analysis |
    Vulnerability awareness |
    Security education
    </p>

    </div>
    """,
    unsafe_allow_html=True
)