# =========================================================
# MITRE ATT&CK Threat Mapping
# =========================================================


MITRE_MAPPINGS = {

    "T1566": {
        "technique": "Phishing",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may use phishing techniques to "
            "gain initial access by sending deceptive messages."
        )
    },


    "T1566.001": {
        "technique": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may send malicious or deceptive "
            "attachments through targeted messages."
        )
    },


    "T1566.002": {
        "technique": "Spearphishing Link",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may use links in messages to "
            "direct users to malicious or deceptive resources."
        )
    },


    "T1059": {
        "technique": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse command and scripting "
            "interpreters to execute commands."
        )
    },


    "T1059.001": {
        "technique": "PowerShell",
        "tactic": "Execution",
        "description": (
            "Adversaries may use PowerShell for command "
            "execution and automation."
        )
    },


    "T1204": {
        "technique": "User Execution",
        "tactic": "Execution",
        "description": (
            "Adversaries may rely on users to execute "
            "malicious files or interact with malicious content."
        )
    },


    "T1204.002": {
        "technique": "Malicious File",
        "tactic": "Execution",
        "description": (
            "Adversaries may rely on users opening or "
            "executing malicious files."
        )
    },


    "T1078": {
        "technique": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence",
        "description": (
            "Adversaries may use legitimate account credentials "
            "to gain unauthorized access."
        )
    },


    "T1110": {
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may attempt to obtain valid account "
            "credentials through repeated authentication attempts."
        )
    },


    "T1190": {
        "technique": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may attempt to exploit vulnerabilities "
            "in applications accessible from the internet."
        )
    },


    "T1486": {
        "technique": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": (
            "Adversaries may encrypt data to disrupt access "
            "and impact availability."
        )
    },


    "T1041": {
        "technique": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": (
            "Adversaries may use an existing command-and-control "
            "channel to transfer collected data."
        )
    },


    "T1082": {
        "technique": "System Information Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may attempt to identify information "
            "about a system and its operating environment."
        )
    },


    "T1083": {
        "technique": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may search for files and directories "
            "on a compromised system."
        )
    },


    "T1053": {
        "technique": "Scheduled Task/Job",
        "tactic": "Persistence / Execution",
        "description": (
            "Adversaries may use scheduled tasks or jobs "
            "to execute programs or maintain persistence."
        )
    },


    "T1105": {
        "technique": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may transfer tools or files into "
            "a compromised environment."
        )
    }

}


def get_mitre_mapping(technique_id):
    """
    Return MITRE ATT&CK information for a technique ID.

    Parameters
    ----------
    technique_id : str
        MITRE ATT&CK technique identifier.

    Returns
    -------
    dict
        Technique, tactic and description.
    """

    if not technique_id:

        return {
            "technique": "Unknown",
            "tactic": "Unknown",
            "description": "No MITRE ATT&CK technique was provided."
        }


    technique_id = str(
        technique_id
    ).strip().upper()


    return MITRE_MAPPINGS.get(
        technique_id,
        {
            "technique": technique_id,
            "tactic": "Not available",
            "description": (
                "MITRE ATT&CK information is not available "
                "in the local mapping dataset."
            )
        }
    )


def get_all_mitre_mappings():
    """
    Return all available MITRE ATT&CK mappings.
    """

    return MITRE_MAPPINGS