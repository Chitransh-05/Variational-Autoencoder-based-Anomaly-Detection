"""Helpers to convert live flow packets into the canonical CICIDS feature vector."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from src.preprocessing.cicids_feature_schema import FEATURE_COLUMNS

try:
    from scapy.layers.inet import IP, TCP, UDP
except Exception:  # pragma: no cover
    IP = TCP = UDP = None


ACTIVE_TIMEOUT_SECONDS = 1.0


def _safe_div(numerator: float, denominator: float, default: float = 0.0) -> float:
    if denominator in (0, None):
        return default
    result = numerator / denominator
    if np.isnan(result) or np.isinf(result):
        return default
    return float(result)


def _safe_stat(values: list[float], op: str, default: float = 0.0) -> float:
    if not values:
        return default
    array = np.asarray(values, dtype=np.float64)
    if op == 'mean':
        result = np.mean(array)
    elif op == 'std':
        result = np.std(array) if len(array) > 1 else default
    elif op == 'max':
        result = np.max(array)
    elif op == 'min':
        result = np.min(array)
    elif op == 'sum':
        result = np.sum(array)
    elif op == 'var':
        result = np.var(array) if len(array) > 1 else default
    else:
        raise ValueError(f'Unsupported op: {op}')
    if np.isnan(result) or np.isinf(result):
        return default
    return float(result)


def _packet_times(packets: list[Any]) -> list[float]:
    return [float(getattr(packet, 'time', 0.0)) for packet in packets if hasattr(packet, 'time')]


def _iat_stats(times: list[float]) -> tuple[float, float, float, float, float]:
    if len(times) <= 1:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    diffs = np.diff(sorted(times))
    diffs = [float(diff) for diff in diffs if not np.isnan(diff) and not np.isinf(diff)]
    return (
        _safe_stat(diffs, 'sum'),
        _safe_stat(diffs, 'mean'),
        _safe_stat(diffs, 'std'),
        _safe_stat(diffs, 'max'),
        _safe_stat(diffs, 'min'),
    )


def _header_length(packet: Any) -> int:
    try:
        ip_header = int(packet[IP].ihl) * 4 if IP and packet.haslayer(IP) else 0
    except Exception:
        ip_header = 0

    try:
        if TCP and packet.haslayer(TCP):
            transport = int(packet[TCP].dataofs) * 4
        elif UDP and packet.haslayer(UDP):
            transport = 8
        else:
            transport = 0
    except Exception:
        transport = 0

    return ip_header + transport


def _tcp_window(packet: Any) -> int:
    try:
        return int(packet[TCP].window) if TCP and packet.haslayer(TCP) else 0
    except Exception:
        return 0


def _payload_length(packet: Any) -> int:
    try:
        if TCP and packet.haslayer(TCP):
            return len(bytes(packet[TCP].payload))
        if UDP and packet.haslayer(UDP):
            return len(bytes(packet[UDP].payload))
    except Exception:
        return 0
    return 0


def _active_idle_stats(times: list[float]) -> tuple[float, float, float, float, float, float]:
    if len(times) <= 1:
        return 0.0, 0.0, 0.0, 0.0, 0.0, 0.0

    sorted_times = sorted(times)
    active_periods = []
    idle_periods = []
    segment_start = sorted_times[0]
    previous = sorted_times[0]

    for current in sorted_times[1:]:
        gap = current - previous
        if gap > ACTIVE_TIMEOUT_SECONDS:
            active_periods.append(previous - segment_start)
            idle_periods.append(gap)
            segment_start = current
        previous = current

    active_periods.append(previous - segment_start)

    return (
        _safe_stat(active_periods, 'mean'),
        _safe_stat(active_periods, 'max'),
        _safe_stat(active_periods, 'min'),
        _safe_stat(idle_periods, 'mean'),
        _safe_stat(idle_periods, 'max'),
        _safe_stat(idle_periods, 'min'),
    )


def build_feature_row(flow: dict[str, Any]) -> dict[str, float]:
    packets = flow.get('packets', [])
    fwd_packets = flow.get('fwd_packets', [])
    bwd_packets = flow.get('bwd_packets', [])

    all_lengths = [len(packet) for packet in packets]
    fwd_lengths = [len(packet) for packet in fwd_packets]
    bwd_lengths = [len(packet) for packet in bwd_packets]

    all_times = _packet_times(packets)
    fwd_times = _packet_times(fwd_packets)
    bwd_times = _packet_times(bwd_packets)

    start_time = float(flow.get('start_time') or 0.0)
    last_seen = float(flow.get('last_seen') or start_time)
    duration_seconds = max(last_seen - start_time, 1e-6)
    duration_microseconds = duration_seconds * 1e6

    total_fwd_bytes = float(flow.get('fwd_bytes', sum(fwd_lengths)))
    total_bwd_bytes = float(flow.get('bwd_bytes', sum(bwd_lengths)))
    total_bytes = total_fwd_bytes + total_bwd_bytes

    flow_iat_total, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _iat_stats(all_times)
    fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _iat_stats(fwd_times)
    bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _iat_stats(bwd_times)
    active_mean, active_max, active_min, idle_mean, idle_max, idle_min = _active_idle_stats(all_times)

    init_fwd_window = _tcp_window(fwd_packets[0]) if fwd_packets else 0
    init_bwd_window = _tcp_window(bwd_packets[0]) if bwd_packets else 0
    act_data_pkt_fwd = sum(1 for packet in fwd_packets if _payload_length(packet) > 0)
    min_seg_size_forward = _safe_stat([_payload_length(packet) for packet in fwd_packets if _payload_length(packet) > 0], 'min')

    flags = flow.get('flags', {})

    row = {
        'Destination Port': float(flow.get('dst_port', 0)),
        'Flow Duration': duration_microseconds,
        'Total Fwd Packets': float(len(fwd_packets)),
        'Total Length of Fwd Packets': total_fwd_bytes,
        'Fwd Packet Length Max': _safe_stat(fwd_lengths, 'max'),
        'Fwd Packet Length Min': _safe_stat(fwd_lengths, 'min'),
        'Fwd Packet Length Mean': _safe_stat(fwd_lengths, 'mean'),
        'Fwd Packet Length Std': _safe_stat(fwd_lengths, 'std'),
        'Bwd Packet Length Max': _safe_stat(bwd_lengths, 'max'),
        'Bwd Packet Length Min': _safe_stat(bwd_lengths, 'min'),
        'Bwd Packet Length Mean': _safe_stat(bwd_lengths, 'mean'),
        'Bwd Packet Length Std': _safe_stat(bwd_lengths, 'std'),
        'Flow Bytes/s': _safe_div(total_bytes, duration_seconds),
        'Flow Packets/s': _safe_div(len(packets), duration_seconds),
        'Flow IAT Mean': flow_iat_mean,
        'Flow IAT Std': flow_iat_std,
        'Flow IAT Max': flow_iat_max,
        'Flow IAT Min': flow_iat_min,
        'Fwd IAT Total': fwd_iat_total,
        'Fwd IAT Mean': fwd_iat_mean,
        'Fwd IAT Std': fwd_iat_std,
        'Fwd IAT Max': fwd_iat_max,
        'Fwd IAT Min': fwd_iat_min,
        'Bwd IAT Total': bwd_iat_total,
        'Bwd IAT Mean': bwd_iat_mean,
        'Bwd IAT Std': bwd_iat_std,
        'Bwd IAT Max': bwd_iat_max,
        'Bwd IAT Min': bwd_iat_min,
        'Fwd Header Length': float(sum(_header_length(packet) for packet in fwd_packets)),
        'Bwd Header Length': float(sum(_header_length(packet) for packet in bwd_packets)),
        'Fwd Packets/s': _safe_div(len(fwd_packets), duration_seconds),
        'Bwd Packets/s': _safe_div(len(bwd_packets), duration_seconds),
        'Min Packet Length': _safe_stat(all_lengths, 'min'),
        'Max Packet Length': _safe_stat(all_lengths, 'max'),
        'Packet Length Mean': _safe_stat(all_lengths, 'mean'),
        'Packet Length Std': _safe_stat(all_lengths, 'std'),
        'Packet Length Variance': _safe_stat(all_lengths, 'var'),
        'FIN Flag Count': float(flags.get('FIN', 0)),
        'PSH Flag Count': float(flags.get('PSH', 0)),
        'ACK Flag Count': float(flags.get('ACK', 0)),
        'Average Packet Size': _safe_div(total_bytes, len(packets)),
        'Subflow Fwd Bytes': total_fwd_bytes,
        'Init_Win_bytes_forward': float(init_fwd_window),
        'Init_Win_bytes_backward': float(init_bwd_window),
        'act_data_pkt_fwd': float(act_data_pkt_fwd),
        'min_seg_size_forward': float(min_seg_size_forward),
        'Active Mean': active_mean,
        'Active Max': active_max,
        'Active Min': active_min,
        'Idle Mean': idle_mean,
        'Idle Max': idle_max,
        'Idle Min': idle_min,
    }

    return row


def extract_feature_vector(flow: dict[str, Any]) -> np.ndarray:
    row = build_feature_row(flow)
    frame = pd.DataFrame([row], columns=FEATURE_COLUMNS).fillna(0.0)
    return frame.iloc[0].to_numpy(dtype=np.float32)
