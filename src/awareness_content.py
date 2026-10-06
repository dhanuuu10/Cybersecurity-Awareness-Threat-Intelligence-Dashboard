# ---------------------------------------------------------
# Cybersecurity Awareness Learning Content
# ---------------------------------------------------------


AWARENESS_TOPICS = {

    "PHISHING": {

        "title": "🎣 Phishing Awareness",

        "description": (
            "Phishing is a social-engineering technique in which "
            "an attacker attempts to trick a user into revealing "
            "information, opening a malicious attachment, or "
            "following a deceptive link."
        ),

        "warning_signs": [
            "Unexpected requests for passwords or sensitive information.",
            "Urgent or threatening messages demanding immediate action.",
            "Suspicious links or unfamiliar domains.",
            "Unexpected attachments.",
            "Messages containing unusual spelling or grammar.",
            "Requests to bypass normal security procedures."
        ],

        "best_practices": [
            "Verify unexpected requests through a trusted channel.",
            "Do not provide passwords or sensitive information through suspicious messages.",
            "Inspect links carefully before opening them.",
            "Use multi-factor authentication.",
            "Report suspicious messages according to organizational procedures."
        ]
    },


    "ACCOUNT SECURITY": {

        "title": "🔐 Account Security",

        "description": (
            "Account security protects user identities and "
            "systems from unauthorized access."
        ),

        "warning_signs": [
            "Unexpected login notifications.",
            "Password-reset messages you did not request.",
            "Unknown devices appearing in account activity.",
            "Repeated failed-login notifications.",
            "Requests to share authentication codes."
        ],

        "best_practices": [
            "Use strong and unique passwords.",
            "Enable multi-factor authentication.",
            "Never share authentication codes.",
            "Review account activity regularly.",
            "Change compromised credentials immediately."
        ]
    },


    "MALWARE": {

        "title": "🦠 Malware Awareness",

        "description": (
            "Malware is malicious software designed to perform "
            "unauthorized or harmful actions on a computer system."
        ),

        "warning_signs": [
            "Unexpected software installation.",
            "Unusual system behavior.",
            "Unknown applications or processes.",
            "Unexpected security warnings.",
            "Unusual file changes."
        ],

        "best_practices": [
            "Keep operating systems and applications updated.",
            "Use reputable security software.",
            "Avoid installing software from untrusted sources.",
            "Do not open unexpected attachments.",
            "Maintain reliable backups."
        ]
    },


    "RANSOMWARE": {

        "title": "🔒 Ransomware Awareness",

        "description": (
            "Ransomware is malware that can make data or systems "
            "unavailable and may demand payment from victims."
        ),

        "warning_signs": [
            "Unexpected file-access problems.",
            "Large numbers of files changing unexpectedly.",
            "Unexpected security alerts.",
            "Unusual system activity.",
            "Messages demanding payment after data becomes unavailable."
        ],

        "best_practices": [
            "Maintain regular offline or protected backups.",
            "Keep systems patched.",
            "Use endpoint security controls.",
            "Limit unnecessary user privileges.",
            "Report suspicious activity quickly."
        ]
    },


    "SOCIAL ENGINEERING": {

        "title": "🧠 Social Engineering Awareness",

        "description": (
            "Social engineering manipulates people into performing "
            "actions that may weaken security."
        ),

        "warning_signs": [
            "Pressure to act immediately.",
            "Requests that bypass normal procedures.",
            "Impersonation of trusted people or organizations.",
            "Requests for confidential information.",
            "Unusual emotional pressure."
        ],

        "best_practices": [
            "Pause before acting on unexpected requests.",
            "Verify identity independently.",
            "Follow established security procedures.",
            "Do not disclose confidential information unnecessarily.",
            "Report suspicious behavior."
        ]
    },


    "WEB SECURITY": {

        "title": "🌐 Web Security Awareness",

        "description": (
            "Web security awareness helps users recognize "
            "unsafe websites, deceptive links, and suspicious "
            "online activity."
        ),

        "warning_signs": [
            "Unexpected redirects.",
            "Suspicious or unfamiliar domains.",
            "Requests for unnecessary personal information.",
            "Browser security warnings.",
            "Unexpected download prompts."
        ],

        "best_practices": [
            "Use trusted websites.",
            "Check the domain carefully.",
            "Keep browsers updated.",
            "Do not ignore browser security warnings.",
            "Avoid downloading unknown files."
        ]
    },


    "DATA PROTECTION": {

        "title": "🛡️ Data Protection Awareness",

        "description": (
            "Data protection involves preventing unauthorized "
            "access, disclosure, modification, or loss of information."
        ),

        "warning_signs": [
            "Sensitive information being shared unnecessarily.",
            "Unknown access to files.",
            "Unexpected data-sharing requests.",
            "Sensitive information stored without protection.",
            "Unauthorized access notifications."
        ],

        "best_practices": [
            "Share sensitive information only when necessary.",
            "Use appropriate access controls.",
            "Protect sensitive files.",
            "Avoid storing confidential information in untrusted locations.",
            "Report suspected data exposure."
        ]
    }
}


def get_awareness_topics():
    """
    Return the available awareness topics.
    """

    return list(
        AWARENESS_TOPICS.keys()
    )


def get_awareness_topic(topic):
    """
    Return awareness content for a selected topic.
    """

    return AWARENESS_TOPICS.get(
        topic
    )