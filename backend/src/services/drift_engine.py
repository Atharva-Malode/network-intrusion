import math
import time
import numpy as np
from typing import List, Dict, Any
from collections import Counter

from src.storage.memory import traffic_events, baseline_events

try:
    from scipy.stats import ks_2samp, wasserstein_distance
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False

ATTACK_IPS_SET = {
    "185.220.101.5", "185.220.101.44", "185.220.102.78", "45.83.223.12",
    "45.83.223.99", "103.21.244.15", "103.21.244.201", "194.26.29.11"
}


def calculate_categorical_psi(baseline_cats: List[str], current_cats: List[str], top_k: int = 10) -> float:
    """
    Calculates Population Stability Index (PSI) with Laplace Smoothing & Floor Probability.
    PSI = sum((Actual% - Expected%) * ln(Actual% / Expected%))
    """
    if not baseline_cats or not current_cats:
        return 0.0

    b_counter = Counter(baseline_cats)
    c_counter = Counter(current_cats)

    most_common_b = [cat for cat, _ in b_counter.most_common(top_k)]
    all_cats = list(set(most_common_b + current_cats[:top_k]))
    if not all_cats:
        return 0.0

    b_total = len(baseline_cats)
    c_total = len(current_cats)
    k_cats = len(all_cats)

    psi_val = 0.0
    laplace_k = 0.5  # Laplace smoothing parameter

    for cat in all_cats:
        exp_prob = (b_counter.get(cat, 0) + laplace_k) / (b_total + laplace_k * k_cats)
        act_prob = (c_counter.get(cat, 0) + laplace_k) / (c_total + laplace_k * k_cats)

        exp_prob = max(0.01, exp_prob)
        act_prob = max(0.01, act_prob)

        psi_val += (act_prob - exp_prob) * math.log(act_prob / exp_prob)

    return round(float(max(0.0, psi_val)), 4)


def numpy_ks_2samp(data1: np.ndarray, data2: np.ndarray):
    """Fallback 2-sample Kolmogorov-Smirnov test using Numpy ECDF."""
    if len(data1) == 0 or len(data2) == 0:
        return 0.0, 1.0
    
    n1, n2 = len(data1), len(data2)
    data1_sorted, data2_sorted = np.sort(data1), np.sort(data2)
    all_vals = np.concatenate([data1_sorted, data2_sorted])
    
    cdf1 = np.searchsorted(data1_sorted, all_vals, side='right') / n1
    cdf2 = np.searchsorted(data2_sorted, all_vals, side='right') / n2
    
    d_stat = float(np.max(np.abs(cdf1 - cdf2)))
    
    en = math.sqrt(n1 * n2 / (n1 + n2))
    lambda_val = (en + 0.12 + 0.11 / en) * d_stat
    p_val = 2.0 * math.exp(-2.0 * lambda_val ** 2)
    p_val = min(1.0, max(0.0, float(p_val)))
    
    return d_stat, p_val


def calculate_drift_metrics() -> Dict[str, Any]:
    """
    Computes statistical concept drift across multiple calibrated techniques:
    1. Kolmogorov-Smirnov Test (Continuous feature distribution test with smooth ECDF)
    2. Population Stability Index (Laplace-smoothed categorical path & threat class shift)
    3. Wasserstein Distance / EMD (Normalized multi-feature geometry distance)
    4. Z-Score Anomaly Shift (3-Sigma rate & metric shift)
    """
    events_list = list(traffic_events)
    baseline_list = list(baseline_events)

    if len(baseline_list) < 20:
        if len(events_list) >= 40:
            split_idx = min(200, len(events_list) // 2)
            baseline_sample = events_list[:split_idx]
            current_sample = events_list[split_idx:]
        else:
            baseline_sample = events_list
            current_sample = events_list
    else:
        baseline_sample = baseline_list
        current_sample = events_list[-100:] if len(events_list) >= 10 else events_list

    if not baseline_sample or not current_sample:
        return {
            "status": "NORMAL",
            "drift_detected": False,
            "overall_drift_score": 0.0,
            "techniques": {
                "ks_test": {"name": "Kolmogorov-Smirnov Test", "statistic": 0.0, "p_value": 1.0, "drift": False, "score": 0.0, "description": "2-sample continuous feature distribution test"},
                "psi": {"name": "Population Stability Index", "score": 0.0, "status": "STABLE", "drift": False, "scaled_score": 0.0, "description": "Laplace-smoothed categorical shift index"},
                "wasserstein": {"name": "Wasserstein Distance (EMD)", "distance": 0.0, "drift": False, "score": 0.0, "description": "Earth Mover's Distance on normalized features"},
                "z_score": {"name": "Z-Score Anomaly", "score": 0.0, "drift": False, "scaled_score": 0.0, "description": "3-Sigma throughput & parameter variance shift"},
            },
            "features": [],
            "sample_counts": {"baseline": len(baseline_sample), "current": len(current_sample)},
            "debug": {
                "psi_contribution": 0.0,
                "ks_contribution": 0.0,
                "wasserstein_contribution": 0.0,
                "z_score_contribution": 0.0,
                "psi_raw": 0.0,
                "ks_raw_d": 0.0,
                "wasserstein_raw_w": 0.0,
                "z_score_raw_z": 0.0,
                "formula_explanation": "Composite Score (0.0%) = 30%*PSI(0) + 25%*KS(0) + 25%*EMD(0) + 20%*Z(0)",
                "baseline_sample_count": len(baseline_sample),
                "current_sample_count": len(current_sample)
            }
        }

    # Extract numerical feature arrays with subtle continuous jitter to prevent discrete ECDF step artifacts
    b_depths = np.array([float(e.path_depth) for e in baseline_sample])
    c_depths = np.array([float(e.path_depth) for e in current_sample])

    b_content = np.array([float(e.content_length) for e in baseline_sample])
    c_content = np.array([float(e.content_length) for e in current_sample])

    b_params = np.array([float(e.query_param_count) for e in baseline_sample])
    c_params = np.array([float(e.query_param_count) for e in current_sample])

    # 1. KS-Test on Path Depths, Content Length, and Query Params
    # Add tiny random jitter (1e-4) to discrete integers for continuous KS-test accuracy
    rng = np.random.default_rng(42)
    b_d_smooth = b_depths + rng.normal(0, 1e-4, size=len(b_depths))
    c_d_smooth = c_depths + rng.normal(0, 1e-4, size=len(c_depths))

    b_p_smooth = b_params + rng.normal(0, 1e-4, size=len(b_params))
    c_p_smooth = c_params + rng.normal(0, 1e-4, size=len(c_params))

    if SCIPY_AVAILABLE and len(b_depths) > 1 and len(c_depths) > 1:
        d_depth, p_depth = ks_2samp(b_d_smooth, c_d_smooth)
        d_content, p_content = ks_2samp(b_content, c_content)
        d_params, p_params = ks_2samp(b_p_smooth, c_p_smooth)
    else:
        d_depth, p_depth = numpy_ks_2samp(b_d_smooth, c_d_smooth)
        d_content, p_content = numpy_ks_2samp(b_content, c_content)
        d_params, p_params = numpy_ks_2samp(b_p_smooth, c_p_smooth)

    max_d_stat = float(max(d_depth, d_content, d_params))
    min_p_val = float(min(p_depth, p_content, p_params))

    # KS Drift requires significant p-value AND meaningful distribution divergence (D > 0.35)
    ks_drift = min_p_val < 0.001 and max_d_stat > 0.35

    # Scale KS score to 0 - 100
    if max_d_stat < 0.20:
        ks_score_scaled = (max_d_stat / 0.20) * 15.0  # 0 to 15
    elif max_d_stat < 0.45:
        ks_score_scaled = 15.0 + ((max_d_stat - 0.20) / 0.25) * 45.0  # 15 to 60
    else:
        ks_score_scaled = 60.0 + min(40.0, ((max_d_stat - 0.45) / 0.35) * 40.0)  # 60 to 100

    # 2. Population Stability Index (PSI)
    b_paths = [e.path for e in baseline_sample]
    c_paths = [e.path for e in current_sample]
    psi_paths = calculate_categorical_psi(b_paths, c_paths)

    b_methods = [e.method for e in baseline_sample]
    c_methods = [e.method for e in current_sample]
    psi_methods = calculate_categorical_psi(b_methods, c_methods)

    # Categorize IP threat classes: "BOTNET_TOR_IP" vs "CLEAN_USER_IP"
    b_ip_classes = ["BOTNET_TOR_IP" if e.ip in ATTACK_IPS_SET else "CLEAN_USER_IP" for e in baseline_sample]
    c_ip_classes = ["BOTNET_TOR_IP" if e.ip in ATTACK_IPS_SET else "CLEAN_USER_IP" for e in current_sample]
    psi_threat_class = calculate_categorical_psi(b_ip_classes, c_ip_classes)

    overall_psi = round(0.45 * psi_paths + 0.40 * psi_threat_class + 0.15 * psi_methods, 4)
    psi_status = "STABLE" if overall_psi < 0.10 else ("MODERATE SHIFT" if overall_psi < 0.25 else "SEVERE DRIFT")
    psi_drift = overall_psi >= 0.25

    # Scale PSI score to 0 - 100
    if overall_psi < 0.10:
        psi_score_scaled = (overall_psi / 0.10) * 15.0  # 0 to 15
    elif overall_psi < 0.25:
        psi_score_scaled = 15.0 + ((overall_psi - 0.10) / 0.15) * 45.0  # 15 to 60
    else:
        psi_score_scaled = 60.0 + min(40.0, ((overall_psi - 0.25) / 0.35) * 40.0)  # 60 to 100

    # 3. Normalized Wasserstein Distance (EMD)
    b_d_norm, c_d_norm = b_depths / 4.0, c_depths / 4.0
    b_p_norm, c_p_norm = b_params / 4.0, c_params / 4.0
    b_c_norm, c_c_norm = b_content / 1500.0, c_content / 1500.0

    if SCIPY_AVAILABLE:
        w_d = wasserstein_distance(b_d_norm, c_d_norm)
        w_p = wasserstein_distance(b_p_norm, c_p_norm)
        w_c = wasserstein_distance(b_c_norm, c_c_norm)
    else:
        w_d = abs(np.mean(b_d_norm) - np.mean(c_d_norm))
        w_p = abs(np.mean(b_p_norm) - np.mean(c_p_norm))
        w_c = abs(np.mean(b_c_norm) - np.mean(c_c_norm))

    w_avg = round(float((w_d + w_p + w_c) / 3.0), 4)
    wasserstein_drift = w_avg >= 0.25

    # Scale Wasserstein score to 0 - 100
    if w_avg < 0.10:
        wasserstein_score_scaled = (w_avg / 0.10) * 15.0  # 0 to 15
    elif w_avg < 0.25:
        wasserstein_score_scaled = 15.0 + ((w_avg - 0.10) / 0.15) * 45.0  # 15 to 60
    else:
        wasserstein_score_scaled = 60.0 + min(40.0, ((w_avg - 0.25) / 0.35) * 40.0)  # 60 to 100

    # 4. Statistical Z-Score Anomaly Shift
    b_duration = max(1.0, (max([e.timestamp for e in baseline_sample]) - min([e.timestamp for e in baseline_sample])) / 1000.0) if len(baseline_sample) > 1 else 10.0
    b_rps = len(baseline_sample) / max(1.0, b_duration)

    c_duration = max(0.5, (max([e.timestamp for e in current_sample]) - min([e.timestamp for e in current_sample])) / 1000.0) if len(current_sample) > 1 else 1.0
    c_rps = len(current_sample) / max(0.2, c_duration)

    b_mean_depth, b_std_depth = np.mean(b_depths), np.std(b_depths)
    c_mean_depth = np.mean(c_depths)

    b_mean_content, b_std_content = np.mean(b_content), np.std(b_content)
    c_mean_content = np.mean(c_content)

    z_rps = abs(c_rps - b_rps) / 8.0  # 8 RPS standard deviation scaling
    z_depth = abs(c_mean_depth - b_mean_depth) / (b_std_depth + 0.2)
    z_content = abs(c_mean_content - b_mean_content) / (b_std_content + 50.0)

    overall_z_score = round(float(max(z_rps, z_depth, z_content)), 3)
    z_drift = overall_z_score >= 3.0

    # Scale Z-Score to 0 - 100
    if overall_z_score < 1.2:
        z_score_scaled = (overall_z_score / 1.2) * 15.0  # 0 to 15
    elif overall_z_score < 3.0:
        z_score_scaled = 15.0 + ((overall_z_score - 1.2) / 1.8) * 45.0  # 15 to 60
    else:
        z_score_scaled = 60.0 + min(40.0, ((overall_z_score - 3.0) / 4.0) * 40.0)  # 60 to 100

    # Weighted Composite Drift Score Calculation
    # Weights: PSI = 30%, KS = 25%, EMD = 25%, Z-Score = 20%
    psi_contrib = 0.30 * psi_score_scaled
    ks_contrib = 0.25 * ks_score_scaled
    emd_contrib = 0.25 * wasserstein_score_scaled
    z_contrib = 0.20 * z_score_scaled

    composite_raw = psi_contrib + ks_contrib + emd_contrib + z_contrib
    overall_drift_score = min(100.0, max(0.0, round(composite_raw, 1)))

    if overall_drift_score > 60.0:
        status = "CRITICAL"
        overall_drift = True
    elif overall_drift_score > 20.0:
        status = "WARNING"
        overall_drift = True
    else:
        status = "NORMAL"
        overall_drift = False

    return {
        "status": status,
        "drift_detected": overall_drift,
        "overall_drift_score": overall_drift_score,
        "techniques": {
            "ks_test": {
                "name": "Kolmogorov-Smirnov Test",
                "statistic": round(max_d_stat, 4),
                "p_value": round(min_p_val, 5),
                "drift": ks_drift,
                "score": round(ks_score_scaled, 1),
                "description": "2-sample continuous distribution test (D > 0.35, p < 0.001)",
            },
            "psi": {
                "name": "Population Stability Index",
                "score": round(overall_psi, 4),
                "status": psi_status,
                "drift": psi_drift,
                "scaled_score": round(psi_score_scaled, 1),
                "description": "Laplace-smoothed categorical path & threat class shift",
            },
            "wasserstein": {
                "name": "Wasserstein Distance (EMD)",
                "distance": round(w_avg, 4),
                "drift": wasserstein_drift,
                "score": round(wasserstein_score_scaled, 1),
                "description": "Earth Mover's Distance across normalized feature geometry",
            },
            "z_score": {
                "name": "Z-Score Anomaly",
                "score": round(overall_z_score, 2),
                "drift": z_drift,
                "scaled_score": round(z_score_scaled, 1),
                "description": "Statistical 3-sigma throughput & path depth variance shift",
            },
        },
        "features": [
            {
                "name": "Path Depth",
                "baseline_avg": round(float(np.mean(b_depths)), 2) if len(b_depths) else 0,
                "current_avg": round(float(np.mean(c_depths)), 2) if len(c_depths) else 0,
                "drift": abs(float(np.mean(c_depths) - np.mean(b_depths))) > 0.8 if len(b_depths) and len(c_depths) else False,
            },
            {
                "name": "Content Length",
                "baseline_avg": round(float(np.mean(b_content)), 1) if len(b_content) else 0,
                "current_avg": round(float(np.mean(c_content)), 1) if len(c_content) else 0,
                "drift": abs(float(np.mean(c_content) - np.mean(b_content))) > 300 if len(b_content) and len(c_content) else False,
            },
            {
                "name": "Query Param Count",
                "baseline_avg": round(float(np.mean(b_params)), 2) if len(b_params) else 0,
                "current_avg": round(float(np.mean(c_params)), 2) if len(c_params) else 0,
                "drift": abs(float(np.mean(c_params) - np.mean(b_params))) > 0.5 if len(b_params) and len(c_params) else False,
            },
        ],
        "sample_counts": {
            "baseline": len(baseline_sample),
            "current": len(current_sample),
        },
        "debug": {
            "psi_contribution": round(psi_contrib, 2),
            "ks_contribution": round(ks_contrib, 2),
            "wasserstein_contribution": round(emd_contrib, 2),
            "z_score_contribution": round(z_contrib, 2),
            "psi_raw": round(overall_psi, 4),
            "ks_raw_d": round(max_d_stat, 4),
            "wasserstein_raw_w": round(w_avg, 4),
            "z_score_raw_z": round(overall_z_score, 3),
            "formula_explanation": f"Composite Score ({overall_drift_score}%) = 30%*PSI({round(psi_score_scaled,1)}) + 25%*KS({round(ks_score_scaled,1)}) + 25%*EMD({round(wasserstein_score_scaled,1)}) + 20%*Z({round(z_score_scaled,1)})",
            "baseline_sample_count": len(baseline_sample),
            "current_sample_count": len(current_sample)
        }
    }


# --- cached drift ---------------------------------------------------------
# calculate_drift_metrics() is a few ms, but under sustained traffic we don't
# need to recompute it on every single ingested request. Cache it briefly so
# high-rate ingestion stays cheap.
_drift_cache: Dict[str, Any] = {"data": None, "ts": 0.0}
_DRIFT_TTL_SEC = 0.5


def get_cached_drift() -> Dict[str, Any]:
    now = time.time()
    if _drift_cache["data"] is None or (now - _drift_cache["ts"]) > _DRIFT_TTL_SEC:
        _drift_cache["data"] = calculate_drift_metrics()
        _drift_cache["ts"] = now
    return _drift_cache["data"]
