"""
Shared NSL-KDD definitions: column schema, categorical columns, and the
canonical attack-label -> 5-class category mapping.

Reference dataset: NSL-KDD (Canadian Institute for Cybersecurity, University of
New Brunswick) - the standard, de-duplicated successor to KDD Cup 99. The
41-feature connection schema and the DoS/Probe/R2L/U2R taxonomy below are the
canonical ones used across the NIDS literature and reference implementations
(e.g. github.com/100divyadg/netdefender, github.com/thinline72/nsl-kdd).
"""

# The 41 connection features, in file order, followed by the label and the
# per-row "difficulty" column that KDDTrain+/KDDTest+ ship with (43 cols total).
FEATURE_COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

ALL_COLUMNS = FEATURE_COLUMNS + ["label", "difficulty"]

# Columns that are strings and must be one-hot encoded.
CATEGORICAL_COLUMNS = ["protocol_type", "service", "flag"]

# Everything else is numeric.
NUMERIC_COLUMNS = [c for c in FEATURE_COLUMNS if c not in CATEGORICAL_COLUMNS]

# Canonical NSL-KDD attack-name -> category mapping.
ATTACK_CATEGORY = {
    # DoS
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS",
    "smurf": "DoS", "teardrop": "DoS", "apache2": "DoS", "udpstorm": "DoS",
    "processtable": "DoS", "worm": "DoS", "mailbomb": "DoS",
    # Probe
    "satan": "Probe", "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe",
    "mscan": "Probe", "saint": "Probe",
    # R2L (remote-to-local: unauthorized access from a remote machine)
    "guess_passwd": "R2L", "ftp_write": "R2L", "imap": "R2L", "phf": "R2L",
    "multihop": "R2L", "warezmaster": "R2L", "warezclient": "R2L", "spy": "R2L",
    "xlock": "R2L", "xsnoop": "R2L", "snmpguess": "R2L", "snmpgetattack": "R2L",
    "httptunnel": "R2L", "sendmail": "R2L", "named": "R2L",
    # U2R (user-to-root: privilege escalation)
    "buffer_overflow": "U2R", "loadmodule": "U2R", "rootkit": "U2R",
    "perl": "U2R", "sqlattack": "U2R", "xterm": "U2R", "ps": "U2R",
    # Benign
    "normal": "Normal",
}

# Stable class order used everywhere (training report, live dashboard colours).
CLASS_ORDER = ["Normal", "DoS", "Probe", "R2L", "U2R"]

# Human-readable descriptions for the dashboard.
CLASS_DESCRIPTIONS = {
    "Normal": "Legitimate traffic - no intrusion signature.",
    "DoS": "Denial of Service - flooding / resource exhaustion.",
    "Probe": "Reconnaissance - scanning, enumeration, fingerprinting.",
    "R2L": "Remote-to-Local - unauthorized remote access (credential / auth abuse).",
    "U2R": "User-to-Root - privilege escalation / remote code execution.",
}


def label_to_category(label: str) -> str:
    """Map a raw NSL-KDD attack label to one of the 5 categories."""
    return ATTACK_CATEGORY.get(str(label).strip().lower(), "Normal")
