"""
Synthetic minority-class generator for the rare NSL-KDD categories (R2L / U2R).

Why this exists
---------------
NSL-KDD is severely imbalanced: KDDTrain+ ships only 995 R2L and 52 U2R rows
against 67k Normal / 46k DoS. The RandomForest therefore learns almost nothing
about the two rare classes (baseline recall ~0.008 R2L, ~0.015 U2R), and the
live demo -- where credential.py drives R2L and exploit.py drives U2R through the
HTTP capture proxy -- effectively never gets an R2L/U2R call out of the model
itself (only the signature fallback saves it).

This module oversamples both rare classes with realistic, feature-consistent
synthetic connection records, in two flavours:

  * "classic"  - mirrors the genuine NSL-KDD R2L/U2R distribution (ftp/telnet/
                 imap services, logged_in sessions, hot/num_root/root_shell
                 indicators). Helps the model generalise on the real KDDTest+.
  * "sensor"   - mirrors exactly what capture-proxy/feature_extractor.py emits
                 for the attack scripts (service=http, flag=REJ, the HTTP-derived
                 content features num_failed_logins / root_shell / num_root /
                 hot). This is what makes the *live* attack scripts land on the
                 rare class in the model, not just the signature tier.

Every row is drawn with jitter so the trees see variation rather than a handful
of duplicated points. The generator is seeded for reproducibility.

Run standalone to dump a CSV:  python synthesize.py [--r2l N] [--u2r N] [--seed S]
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from nsl_kdd import FEATURE_COLUMNS

HERE = Path(__file__).parent
DATA_DIR = HERE / "data"

# Fraction of each rare class generated in the HTTP "sensor" flavour (the rest
# is the classic ftp/telnet flavour). The sensor flavour is what ties the model
# to the live capture proxy + attack scripts.
SENSOR_FRACTION = 0.5

# Attacker-style HTTP service segments the sensor derives from the auth/exploit
# paths (feature_extractor._service_key). Kept generic; the model one-hot
# encodes `service`, and the live proxy always emits "http", so the sensor
# flavour uses "http" to match it exactly.
_SENSOR_SERVICE = "http"


def _blank_rows(n: int) -> dict:
    """A dict of zero-filled feature arrays (categoricals get safe defaults)."""
    cols = {c: np.zeros(n) for c in FEATURE_COLUMNS}
    cols["protocol_type"] = np.array(["tcp"] * n, dtype=object)
    cols["service"] = np.array(["http"] * n, dtype=object)
    cols["flag"] = np.array(["SF"] * n, dtype=object)
    return cols


def _pick(rng: np.random.Generator, choices, n, p=None):
    return rng.choice(np.array(choices, dtype=object), size=n, p=p)


def _fill_shape_features(rng: np.random.Generator, c: dict, n: int,
                         rerror_lo: float = 0.3) -> None:
    """Populate the time/host traffic-SHAPE features of an HTTP-sensor row with
    broad, INDEPENDENT random draws (mutates `c` in place).

    The rare classes in the HTTP sensor's feature space are defined by CONTENT
    indicators (num_failed_logins for R2L; root_shell / num_root for U2R), not by
    traffic shape. Attack pacing (count), endpoint spread (same_srv_rate) and
    origin health (serror/rerror) vary freely and must not flip the verdict, so
    we spread them across their whole plausible range rather than tying them to
    a single scenario. `rerror_lo` keeps the 4xx-heavy error floor these attack
    scans always produce (auth 401/403, RCE 404)."""
    c["count"] = rng.integers(2, 150, n)
    c["same_srv_rate"] = rng.uniform(0.0, 1.0, n).round(4)
    c["srv_count"] = (c["count"] * c["same_srv_rate"]).round().clip(1)
    c["diff_srv_rate"] = (1 - c["same_srv_rate"]).round(4)
    c["srv_diff_host_rate"] = rng.uniform(0.0, 1.0, n).round(4)
    c["serror_rate"] = rng.uniform(0.0, 0.7, n).round(4)
    c["srv_serror_rate"] = rng.uniform(0.0, 0.7, n).round(4)
    c["rerror_rate"] = rng.uniform(rerror_lo, 1.0, n).round(4)
    c["srv_rerror_rate"] = rng.uniform(rerror_lo, 1.0, n).round(4)
    c["dst_host_count"] = rng.integers(5, 255, n)
    c["dst_host_same_srv_rate"] = rng.uniform(0.0, 1.0, n).round(4)
    c["dst_host_srv_count"] = (c["dst_host_count"] * c["dst_host_same_srv_rate"]).round().clip(1)
    c["dst_host_diff_srv_rate"] = (1 - c["dst_host_same_srv_rate"]).round(4)
    c["dst_host_same_src_port_rate"] = rng.uniform(0.0, 1.0, n).round(4)
    c["dst_host_srv_diff_host_rate"] = rng.uniform(0.0, 1.0, n).round(4)
    c["dst_host_serror_rate"] = rng.uniform(0.0, 0.7, n).round(4)
    c["dst_host_srv_serror_rate"] = rng.uniform(0.0, 0.7, n).round(4)
    c["dst_host_rerror_rate"] = rng.uniform(rerror_lo, 1.0, n).round(4)
    c["dst_host_srv_rerror_rate"] = rng.uniform(rerror_lo, 1.0, n).round(4)


# --------------------------------------------------------------------------- #
# R2L (remote-to-local: credential / auth abuse, guest-login file transfer)
# --------------------------------------------------------------------------- #
def _r2l_classic(rng: np.random.Generator, n: int) -> pd.DataFrame:
    """Genuine NSL-KDD R2L shape: ftp/telnet sessions, logged_in, occasional
    failed logins and guest logins, high same_srv_rate."""
    c = _blank_rows(n)
    c["service"] = _pick(rng, ["ftp_data", "ftp", "telnet", "imap4", "pop_3", "login"],
                         n, p=[0.45, 0.30, 0.12, 0.05, 0.04, 0.04])
    c["flag"] = _pick(rng, ["SF", "RSTO", "RSTR"], n, p=[0.90, 0.07, 0.03])
    c["duration"] = rng.gamma(shape=1.2, scale=120, size=n).round().clip(0, 15000)
    c["src_bytes"] = rng.gamma(shape=1.1, scale=800, size=n).round().clip(0, 500000)
    c["dst_bytes"] = rng.gamma(shape=1.0, scale=400, size=n).round().clip(0, 200000)
    c["hot"] = rng.choice([0, 1, 2, 3, 4, 8], n, p=[0.55, 0.18, 0.12, 0.07, 0.05, 0.03])
    # The defining R2L signal: failed authentication attempts.
    c["num_failed_logins"] = rng.choice([0, 1, 2, 3, 4, 5], n,
                                        p=[0.45, 0.30, 0.12, 0.07, 0.04, 0.02])
    c["logged_in"] = (c["num_failed_logins"] == 0).astype(int) * \
        rng.choice([0, 1], n, p=[0.15, 0.85])
    c["is_guest_login"] = rng.choice([0, 1], n, p=[0.65, 0.35])
    c["num_compromised"] = rng.choice([0, 1, 2], n, p=[0.9, 0.07, 0.03])
    c["count"] = rng.choice([1, 2, 3, 4], n, p=[0.8, 0.13, 0.05, 0.02])
    c["srv_count"] = c["count"] + rng.choice([0, 1, 2], n, p=[0.85, 0.1, 0.05])
    c["same_srv_rate"] = rng.uniform(0.7, 1.0, n).round(2)
    c["diff_srv_rate"] = (1 - c["same_srv_rate"]).round(2)
    c["dst_host_count"] = rng.integers(1, 255, n)
    c["dst_host_srv_count"] = rng.integers(1, 255, n)
    c["dst_host_same_srv_rate"] = rng.uniform(0.4, 1.0, n).round(2)
    c["dst_host_same_src_port_rate"] = rng.uniform(0.0, 1.0, n).round(2)
    return pd.DataFrame(c)


def _r2l_sensor(rng: np.random.Generator, n: int) -> pd.DataFrame:
    """What the HTTP capture proxy emits for credential.py: service=http,
    REJ flag (auth path 404s), num_failed_logins=1, high rerror_rate."""
    c = _blank_rows(n)
    c["service"] = _SENSOR_SERVICE
    # credential.py hits non-existent auth routes -> mostly 404 (REJ), a few
    # 401/403 (also REJ) and occasional server errors (S0).
    c["flag"] = _pick(rng, ["REJ", "S0"], n, p=[0.9, 0.1])
    c["duration"] = np.zeros(n)
    c["src_bytes"] = rng.integers(40, 160, n)      # small JSON credential body
    c["dst_bytes"] = rng.integers(120, 800, n)     # small error page
    # Sensor sets failed_login=1 on any non-2xx auth request. Occasionally the
    # window carries a couple stacked attempts.
    c["num_failed_logins"] = rng.choice([1, 2, 3], n, p=[0.8, 0.15, 0.05])
    c["logged_in"] = np.zeros(n)
    # The traffic-SHAPE features must NOT gate the R2L call. credential.py hits
    # several different auth endpoints (low same_srv_rate), at any intensity
    # (trickle to burst -> any count), and slow/failing origins add serrors on
    # top of the auth rerrors. So every shape feature is drawn INDEPENDENTLY
    # across its full plausible range; only num_failed_logins is pinned. This
    # forces the trees to key the R2L call on the failed-login content signal,
    # not on the rate/error mix -- robust to attack pacing and origin health.
    _fill_shape_features(rng, c, n, rerror_lo=0.4)
    return pd.DataFrame(c)


# --------------------------------------------------------------------------- #
# U2R (user-to-root: privilege escalation, RCE / traversal / sensitive files)
# --------------------------------------------------------------------------- #
def _u2r_classic(rng: np.random.Generator, n: int) -> pd.DataFrame:
    """Genuine NSL-KDD U2R shape: telnet/ftp session, logged_in, root_shell +
    num_root + num_file_creations + num_shells + hot indicators."""
    c = _blank_rows(n)
    c["service"] = _pick(rng, ["telnet", "ftp_data", "ftp", "other"],
                         n, p=[0.62, 0.24, 0.08, 0.06])
    c["flag"] = _pick(rng, ["SF", "RSTO"], n, p=[0.97, 0.03])
    c["duration"] = rng.gamma(shape=1.3, scale=70, size=n).round().clip(0, 800)
    c["src_bytes"] = rng.gamma(shape=1.2, scale=300, size=n).round().clip(0, 7000)
    c["dst_bytes"] = rng.gamma(shape=1.1, scale=2500, size=n).round().clip(0, 70000)
    c["logged_in"] = rng.choice([0, 1], n, p=[0.12, 0.88])
    c["hot"] = rng.choice([0, 1, 2, 3, 4, 5], n, p=[0.15, 0.4, 0.2, 0.13, 0.08, 0.04])
    c["root_shell"] = rng.choice([0, 1], n, p=[0.5, 0.5])
    c["num_root"] = rng.choice([0, 1, 2, 3, 6, 14], n,
                              p=[0.45, 0.25, 0.15, 0.08, 0.05, 0.02])
    c["num_compromised"] = rng.choice([0, 1, 2, 6], n, p=[0.4, 0.35, 0.18, 0.07])
    c["num_file_creations"] = rng.choice([0, 1, 2, 4], n, p=[0.45, 0.35, 0.15, 0.05])
    c["num_shells"] = rng.choice([0, 1, 2], n, p=[0.82, 0.15, 0.03])
    c["num_access_files"] = rng.choice([0, 1], n, p=[0.85, 0.15])
    c["su_attempted"] = rng.choice([0, 1], n, p=[0.9, 0.1])
    c["count"] = rng.choice([1, 2, 3], n, p=[0.85, 0.1, 0.05])
    c["srv_count"] = c["count"]
    c["same_srv_rate"] = rng.uniform(0.8, 1.0, n).round(2)
    c["dst_host_count"] = rng.integers(1, 255, n)
    c["dst_host_srv_count"] = rng.integers(1, 90, n)
    c["dst_host_same_srv_rate"] = rng.uniform(0.5, 1.0, n).round(2)
    return pd.DataFrame(c)


def _u2r_sensor(rng: np.random.Generator, n: int) -> pd.DataFrame:
    """What the HTTP capture proxy emits for exploit.py: service=http, RCE
    tokens -> root_shell=1, num_root/num_compromised>0, hot>0, logged_in=1."""
    c = _blank_rows(n)
    c["service"] = _SENSOR_SERVICE
    c["flag"] = _pick(rng, ["REJ", "S0", "SF"], n, p=[0.8, 0.1, 0.1])
    c["duration"] = np.zeros(n)
    c["src_bytes"] = rng.integers(20, 200, n)
    c["dst_bytes"] = rng.integers(120, 900, n)
    # rce_hits = number of RCE/traversal tokens in the URL (exploit paths carry 1-3).
    rce = rng.choice([1, 2, 3], n, p=[0.4, 0.4, 0.2])
    # sensitive-path hits (hot = SENSITIVE_PATHS matches + rce_hits in the sensor).
    sens = rng.choice([0, 1, 2], n, p=[0.4, 0.45, 0.15])
    c["hot"] = sens + rce
    c["num_compromised"] = rce
    c["num_root"] = rce
    c["root_shell"] = np.ones(n)
    c["num_shells"] = np.ones(n)
    c["num_access_files"] = sens
    c["num_file_creations"] = rng.choice([0, 1], n, p=[0.6, 0.4])  # POST/PUT exploits
    c["logged_in"] = np.ones(n)                                    # sensor: rce -> logged_in
    # Same reasoning as R2L: exploit.py sprays many distinct RCE paths (low
    # same_srv_rate, high diff_srv_rate) at any rate, and timeouts under load add
    # serrors. All shape features are drawn INDEPENDENTLY over their full range
    # so the RCE content indicators (root_shell / num_root / num_shells) own the
    # U2R call regardless of the traffic shape.
    _fill_shape_features(rng, c, n, rerror_lo=0.3)
    return pd.DataFrame(c)


# --------------------------------------------------------------------------- #
# Shape-based classes in the HTTP-sensor feature space (Normal / Probe / DoS)
#
# Unlike R2L/U2R (defined by CONTENT indicators), these three are defined by
# traffic SHAPE. The genuine NSL-KDD rows teach the model the packet/flow shape
# of these classes, but the live HTTP proxy emits a *different* shape for them
# (service is always "http"; the rate/error features are derived from HTTP
# status + path windowing). Without sensor-flavour rows the model does not
# recognise the live proxy's Probe shape at all (it reads recon as Normal) and
# only recognises DoS via the volumetric signature backstop. These generators
# mirror EXACTLY what capture-proxy/feature_extractor.py emits for the three
# non-content attack scripts so the model itself owns the live call.
#
#   sensor separators (all have content_score == 0):
#     Normal : flag SF, rerror ~0,   low count,        moderate same_srv
#     Probe  : flag REJ, rerror HIGH, elevated count,  LOW same_srv / HIGH diff_srv
#     DoS    : flag SF/S0, rerror ~0, VERY HIGH count,  same_srv ~1.0 / some serror
# --------------------------------------------------------------------------- #
def _normal_sensor(rng: np.random.Generator, n: int) -> pd.DataFrame:
    """What the HTTP proxy emits for normal.py: legitimate browsing of a handful
    of real pages -> 200 (SF), no auth/RCE tokens, no 4xx errors, low rate."""
    c = _blank_rows(n)
    c["service"] = _SENSOR_SERVICE
    c["flag"] = _pick(rng, ["SF", "SF", "SF", "S0"], n, p=[0.4, 0.3, 0.25, 0.05])
    c["duration"] = rng.uniform(0.0, 0.5, n).round(4)
    c["src_bytes"] = rng.integers(0, 60, n)          # GET, no body
    c["dst_bytes"] = rng.integers(200, 9000, n)       # a rendered page
    # A human browses a few distinct pages slowly -> low count in the 2s window.
    c["count"] = rng.integers(1, 12, n)
    c["same_srv_rate"] = rng.uniform(0.1, 1.0, n).round(4)
    c["srv_count"] = (c["count"] * c["same_srv_rate"]).round().clip(1)
    c["diff_srv_rate"] = (1 - c["same_srv_rate"]).round(4)
    c["srv_diff_host_rate"] = rng.uniform(0.0, 0.4, n).round(4)
    # The defining Normal separators: successful requests -> ~no rerror/serror.
    c["serror_rate"] = rng.uniform(0.0, 0.05, n).round(4)
    c["srv_serror_rate"] = rng.uniform(0.0, 0.05, n).round(4)
    c["rerror_rate"] = rng.uniform(0.0, 0.05, n).round(4)
    c["srv_rerror_rate"] = rng.uniform(0.0, 0.05, n).round(4)
    c["dst_host_count"] = rng.integers(1, 120, n)
    c["dst_host_same_srv_rate"] = rng.uniform(0.2, 1.0, n).round(4)
    c["dst_host_srv_count"] = (c["dst_host_count"] * c["dst_host_same_srv_rate"]).round().clip(1)
    c["dst_host_diff_srv_rate"] = (1 - c["dst_host_same_srv_rate"]).round(4)
    c["dst_host_same_src_port_rate"] = rng.uniform(0.0, 1.0, n).round(4)
    c["dst_host_srv_diff_host_rate"] = rng.uniform(0.0, 0.3, n).round(4)
    c["dst_host_serror_rate"] = rng.uniform(0.0, 0.05, n).round(4)
    c["dst_host_srv_serror_rate"] = rng.uniform(0.0, 0.05, n).round(4)
    c["dst_host_rerror_rate"] = rng.uniform(0.0, 0.05, n).round(4)
    c["dst_host_srv_rerror_rate"] = rng.uniform(0.0, 0.05, n).round(4)
    return pd.DataFrame(c)


def _probe_sensor(rng: np.random.Generator, n: int) -> pd.DataFrame:
    """What the HTTP proxy emits for recon.py: many DISTINCT endpoints, mostly
    404 (REJ) -> high rerror_rate, LOW same_srv_rate / HIGH diff_srv_rate,
    elevated count from the concurrent scan. No content indicators."""
    c = _blank_rows(n)
    c["service"] = _SENSOR_SERVICE
    c["flag"] = _pick(rng, ["REJ", "REJ", "S0"], n, p=[0.8, 0.12, 0.08])
    c["duration"] = rng.uniform(0.0, 0.3, n).round(4)
    c["src_bytes"] = rng.integers(0, 60, n)           # GET scan, no body
    c["dst_bytes"] = rng.integers(100, 1400, n)        # small 404 pages
    # Concurrent scanner (12 workers) -> elevated count in the 2s window.
    c["count"] = rng.integers(12, 160, n)
    # The defining Probe separators: spraying many distinct services.
    c["same_srv_rate"] = rng.uniform(0.02, 0.35, n).round(4)
    c["srv_count"] = (c["count"] * c["same_srv_rate"]).round().clip(1)
    c["diff_srv_rate"] = (1 - c["same_srv_rate"]).round(4)
    c["srv_diff_host_rate"] = rng.uniform(0.0, 0.9, n).round(4)
    c["serror_rate"] = rng.uniform(0.0, 0.2, n).round(4)
    c["srv_serror_rate"] = rng.uniform(0.0, 0.3, n).round(4)
    c["rerror_rate"] = rng.uniform(0.7, 1.0, n).round(4)      # 404 storm
    c["srv_rerror_rate"] = rng.uniform(0.6, 1.0, n).round(4)
    c["dst_host_count"] = rng.integers(40, 255, n)
    c["dst_host_same_srv_rate"] = rng.uniform(0.02, 0.4, n).round(4)
    c["dst_host_srv_count"] = (c["dst_host_count"] * c["dst_host_same_srv_rate"]).round().clip(1)
    c["dst_host_diff_srv_rate"] = (1 - c["dst_host_same_srv_rate"]).round(4)
    c["dst_host_same_src_port_rate"] = rng.uniform(0.0, 0.8, n).round(4)
    c["dst_host_srv_diff_host_rate"] = rng.uniform(0.0, 0.9, n).round(4)
    c["dst_host_serror_rate"] = rng.uniform(0.0, 0.2, n).round(4)
    c["dst_host_srv_serror_rate"] = rng.uniform(0.0, 0.3, n).round(4)
    c["dst_host_rerror_rate"] = rng.uniform(0.6, 1.0, n).round(4)
    c["dst_host_srv_rerror_rate"] = rng.uniform(0.6, 1.0, n).round(4)
    return pd.DataFrame(c)


def _dos_sensor(rng: np.random.Generator, n: int) -> pd.DataFrame:
    """What the HTTP proxy emits for flood.py: one endpoint hammered at high
    concurrency -> VERY HIGH count, same_srv_rate ~1.0, low rerror (200s), some
    serror once the origin saturates and times out (S0). No content indicators."""
    c = _blank_rows(n)
    c["service"] = _SENSOR_SERVICE
    c["flag"] = _pick(rng, ["SF", "S0", "SF"], n, p=[0.6, 0.3, 0.1])
    c["duration"] = rng.uniform(0.0, 1.0, n).round(4)
    c["src_bytes"] = rng.integers(0, 40, n)            # GET flood, no body
    c["dst_bytes"] = rng.integers(0, 5000, n)          # page, or 0 on timeout
    # The defining DoS separator: sustained very high rate to ONE service.
    c["count"] = rng.integers(40, 800, n)
    c["same_srv_rate"] = rng.uniform(0.85, 1.0, n).round(4)
    c["srv_count"] = (c["count"] * c["same_srv_rate"]).round().clip(1)
    c["diff_srv_rate"] = (1 - c["same_srv_rate"]).round(4)
    c["srv_diff_host_rate"] = rng.uniform(0.0, 1.0, n).round(4)
    # Timeouts under load -> S0 -> serror; 200s -> low rerror.
    c["serror_rate"] = rng.uniform(0.0, 0.5, n).round(4)
    c["srv_serror_rate"] = rng.uniform(0.0, 0.5, n).round(4)
    c["rerror_rate"] = rng.uniform(0.0, 0.1, n).round(4)
    c["srv_rerror_rate"] = rng.uniform(0.0, 0.1, n).round(4)
    c["dst_host_count"] = rng.integers(100, 255, n)
    c["dst_host_same_srv_rate"] = rng.uniform(0.85, 1.0, n).round(4)
    c["dst_host_srv_count"] = (c["dst_host_count"] * c["dst_host_same_srv_rate"]).round().clip(1)
    c["dst_host_diff_srv_rate"] = (1 - c["dst_host_same_srv_rate"]).round(4)
    c["dst_host_same_src_port_rate"] = rng.uniform(0.0, 1.0, n).round(4)
    c["dst_host_srv_diff_host_rate"] = rng.uniform(0.0, 1.0, n).round(4)
    c["dst_host_serror_rate"] = rng.uniform(0.0, 0.5, n).round(4)
    c["dst_host_srv_serror_rate"] = rng.uniform(0.0, 0.5, n).round(4)
    c["dst_host_rerror_rate"] = rng.uniform(0.0, 0.1, n).round(4)
    c["dst_host_srv_rerror_rate"] = rng.uniform(0.0, 0.1, n).round(4)
    return pd.DataFrame(c)


def synthesize_rare(n_r2l: int = 4000, n_u2r: int = 3000,
                    seed: int = 42, sensor_fraction: float = SENSOR_FRACTION,
                    n_normal: int = 0, n_probe: int = 0, n_dos: int = 0) -> pd.DataFrame:
    """Return a DataFrame of synthetic augmentation rows (FEATURE_COLUMNS + category).

    R2L / U2R are split between the classic (ftp/telnet) and sensor (http)
    flavours so the model learns both the genuine NSL-KDD shape and the live-proxy
    shape. Normal / Probe / DoS are generated purely in the HTTP-sensor flavour
    (n_normal / n_probe / n_dos > 0) so the model recognises the live proxy's
    traffic shape for those classes too — genuine NSL-KDD already covers their
    packet/flow shape, so only the sensor flavour is added here.
    """
    rng = np.random.default_rng(seed)
    frames = []

    r2l_sensor_n = int(round(n_r2l * sensor_fraction))
    u2r_sensor_n = int(round(n_u2r * sensor_fraction))

    parts = [
        (_r2l_classic(rng, n_r2l - r2l_sensor_n), "R2L"),
        (_r2l_sensor(rng, r2l_sensor_n), "R2L"),
        (_u2r_classic(rng, n_u2r - u2r_sensor_n), "U2R"),
        (_u2r_sensor(rng, u2r_sensor_n), "U2R"),
        (_normal_sensor(rng, n_normal), "Normal"),
        (_probe_sensor(rng, n_probe), "Probe"),
        (_dos_sensor(rng, n_dos), "DoS"),
    ]
    for df, cat in parts:
        if len(df) == 0:
            continue
        df = df.copy()
        df["category"] = cat
        frames.append(df)

    out = pd.concat(frames, ignore_index=True)
    # Guarantee canonical column order + dtypes the pipeline expects.
    out = out[FEATURE_COLUMNS + ["category"]]
    for col in FEATURE_COLUMNS:
        if col not in ("protocol_type", "service", "flag"):
            out[col] = pd.to_numeric(out[col])
    return out.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate synthetic augmentation rows.")
    ap.add_argument("--r2l", type=int, default=4000)
    ap.add_argument("--u2r", type=int, default=3000)
    ap.add_argument("--normal", type=int, default=0)
    ap.add_argument("--probe", type=int, default=0)
    ap.add_argument("--dos", type=int, default=0)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=str(DATA_DIR / "synthetic_rare.csv"))
    args = ap.parse_args()

    df = synthesize_rare(args.r2l, args.u2r, args.seed,
                         n_normal=args.normal, n_probe=args.probe, n_dos=args.dos)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.out, index=False)
    print(f"[synth] wrote {len(df):,} rows -> {args.out}")
    print(df["category"].value_counts().to_string())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
