"""What we make of a SYN fingerprint.

Two things, both fed by the fields zardaxt.py records for a SYN:

  1. OS guess (`make_os_guess`): the SYN is scored against every fingerprint
     in database/newCleaned.json and averaged per operating system. This is
     the classic zardaxt output (`avg_score_os_class`).

  2. Relay verdict (`MismatchModel`): given the browser's User-Agent, how
     likely is it that the SYN was sent by a proxy rather than by the machine
     the User-Agent describes. A gradient-boosting model trained on labelled
     connections; its feature layout is defined here so training and serving
     cannot drift.
"""
import json
import re
from pathlib import Path

from log import log

ROOT = Path(__file__).resolve().parent.parent
DATABASE_FILE = ROOT / 'database' / 'newCleaned.json'
MODEL_FILE = ROOT / 'models' / 'tcpip_mismatch.joblib'

# TCP control flags
TH_FIN, TH_SYN, TH_RST, TH_PUSH, TH_ACK, TH_URG, TH_ECE, TH_CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80

OS_CLASSES = ['Linux', 'Mac OS', 'Windows', 'iOS']

# The operating system a User-Agent claims, in the four classes the database
# and the model know. Android and Chrome OS are Linux: same kernel, same SYN.
# Order matters: iOS before Mac OS (iPhone UAs say "like Mac OS X").
_UA_OS = [
    (re.compile(r'iPhone|iPad|iPod'), 'iOS'),
    (re.compile(r'Windows'), 'Windows'),
    (re.compile(r'Mac OS X|Macintosh'), 'Mac OS'),
    (re.compile(r'Android|HarmonyOS|CrOS|Linux|X11|Ubuntu|Fedora|Debian'), 'Linux'),
]


def ua_os(user_agent):
    """'Windows', 'Mac OS', 'iOS', 'Linux' or None."""
    if not user_agent:
        return None
    for pattern, name in _UA_OS:
        if pattern.search(user_agent):
            return name
    return None


def near_ttl(ip_ttl):
    """The initial TTL the sender most likely used (64 Unix, 128 Windows, ...)."""
    if ip_ttl is None:
        return -1
    if ip_ttl <= 32:
        return 32
    if ip_ttl <= 64:
        return 64
    if ip_ttl <= 128:
        return 128
    return 255


def normalize_fp(fp):
    """Bucket the fields that vary per connection but not per OS."""
    n = dict(fp)
    n['ip_ttl'] = near_ttl(fp.get('ip_ttl'))
    n['ip_id'] = 0 if fp.get('ip_id') == 0 else 1
    n['tcp_timestamp'] = 0 if fp.get('tcp_timestamp') in ('', None) else 1
    n['tcp_timestamp_echo_reply'] = 0 if fp.get('tcp_timestamp_echo_reply') in ('', None) else 1
    return n


# ---- OS guess from the fingerprint database ----------------------------------

_db = []
_db_count = {}


def load_database(path=DATABASE_FILE):
    """Entries carry `n`, the number of sessions that produced the fingerprint
    (database/prepare.js); databases without it weight every entry equally."""
    global _db, _db_count
    with open(path) as f:
        _db = json.load(f)
    _db_count = {}
    for e in _db:
        _db_count[e['os']] = _db_count.get(e['os'], 0) + e.get('n', 1)
    log(f'loaded {len(_db)} fingerprints from {sum(_db_count.values())} sessions: {_db_count}', 'fingerprint')


def score_fp(fp):
    """Similarity of the (normalized) fingerprint to each OS's fingerprints,
    averaged over the sessions behind them."""
    totals = {os_name: 0.0 for os_name in _db_count}
    for e in _db:
        s = 0.0
        s += 1.5 if e['ip_id'] == fp['ip_id'] else 0
        s += 0.25 if e['ip_tos'] == fp['ip_tos'] else 0
        s += 2.5 if e['ip_total_length'] == fp['ip_total_length'] else 0
        s += 2 if e['ip_ttl'] == fp['ip_ttl'] else 0
        s += 2.5 if e['tcp_off'] == fp['tcp_off'] else 0
        s += 2 if e['tcp_timestamp_echo_reply'] == fp['tcp_timestamp_echo_reply'] else 0
        s += 2 if e['tcp_window_scaling'] == fp['tcp_window_scaling'] else 0
        s += 2 if e['tcp_window_size'] == fp['tcp_window_size'] else 0
        s += 0.25 if e['tcp_flags'] == fp['tcp_flags'] else 0
        s += 1.5 if e['tcp_mss'] == fp['tcp_mss'] else 0
        if e['tcp_options'] == fp['tcp_options']:
            s += 4
        elif e['tcp_options_ordered'] == fp['tcp_options_ordered']:
            s += 2.5
        totals[e['os']] += s * e.get('n', 1)
    return {os_name: round(totals[os_name] / _db_count[os_name], 2) for os_name in totals}


def make_os_guess(fp):
    avg = score_fp(normalize_fp(fp))
    return {
        'avg_score_os_class': avg,
        'fp': fp,
        'details': {
            'os_highest_class': max(avg, key=avg.get),
            'highest_os_avg': max(avg.values()),
            'perfect_score': 20.5,
        },
    }


# ---- relay verdict: SYN + User-Agent -> proxy? --------------------------------

NUMERIC_FEATURES = ['ttl_bucket', 'ip_id_zero', 'ip_tos', 'ip_total_length', 'tcp_off', 'tcp_window_scaling',
                    'tcp_window_size', 'tcp_mss', 'tcp_flags', 'tcp_timestamp', 'ip_df']
CATEGORICAL_FEATURES = ['tcp_options', 'tcp_options_ordered', 'ua_os']
FEATURES = NUMERIC_FEATURES + CATEGORICAL_FEATURES


def _num(value, default=-1.0):
    return float(default if value is None or value == '' else value)


def feature_vector(fp, os_name, vocabs):
    """One row for the model. `vocabs` maps each categorical feature to
    {value: index}; unknown values take the 'other' index."""
    ordered = fp.get('tcp_options_ordered') or ''.join(t[0] for t in (fp.get('tcp_options') or '').split(',') if t)
    row = [
        float(near_ttl(fp.get('ip_ttl'))),
        1.0 if fp.get('ip_id') == 0 else 0.0,
        _num(fp.get('ip_tos')),
        _num(fp.get('ip_total_length')),
        _num(fp.get('tcp_off')),
        _num(fp.get('tcp_window_scaling')),
        _num(fp.get('tcp_window_size')),
        _num(fp.get('tcp_mss')),
        _num(fp.get('tcp_flags')),
        0.0 if fp.get('tcp_timestamp') in ('', None) else 1.0,
        _num(fp.get('ip_df')),
    ]
    for name, value in (('tcp_options', fp.get('tcp_options') or ''), ('tcp_options_ordered', ordered), ('ua_os', os_name or 'unknown')):
        vocab = vocabs[name]
        row.append(float(vocab.get(value, vocab['other'])))
    return row


class MismatchModel:
    """Loads models/tcpip_mismatch.joblib if present; otherwise `predict` returns None."""

    def __init__(self, path=MODEL_FILE):
        self.artifact = None
        if not Path(path).exists():
            log(f'no relay model at {path}, serving the OS guess only', 'fingerprint')
            return
        try:
            import joblib
            self.artifact = joblib.load(path)
            m = self.artifact.get('metrics', {})
            log(f"loaded relay model {path.name}: trained {self.artifact.get('trained_at')}, threshold {self.artifact['threshold']}, "
                f"held-out FPR {m.get('fpr_clean')} recall {m.get('recall')}", 'fingerprint')
        except Exception as err:  # missing sklearn, version mismatch, corrupt file
            log(f'cannot load relay model {path}: {err}', 'fingerprint', level='ERROR')
            self.artifact = None

    @property
    def loaded(self):
        return self.artifact is not None

    def predict(self, fp, user_agent):
        """{ probability, threshold, flagged, ua_os } or None without model or User-Agent."""
        os_name = ua_os(user_agent)
        if not self.loaded or not os_name:
            return None
        a = self.artifact
        row = feature_vector(fp, os_name, a['vocabs'])
        probability = float(a['model'].predict_proba([row])[0][1])
        return {
            'probability': round(probability, 4),
            'threshold': a['threshold'],
            'flagged': probability >= a['threshold'],
            'ua_os': os_name,
        }
