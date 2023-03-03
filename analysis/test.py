import pandas as pd
import matplotlib.pyplot as plt
import json

"""
  {'Android': 2501, 'Linux': 2501, 'Mac OS': 2501, 'Windows': 2501, 'iOS': 2501}
"""

df = pd.read_csv('../database/tcp_ip.csv')
print(df)

clusters = ["Android", "Linux", "Mac OS", "Windows", "iOS"]
remaining = ['ip_checksum', 'ip_df', 'ip_hdr_length',
             'ip_mf', 'ip_off', 'ip_protocol', 'ip_rf', 'ip_tos',
             'ip_total_length', 'ip_version', 'tcp_ack', 'tcp_checksum',
             'tcp_flags', 'tcp_header_length', 'tcp_mss', 'tcp_off', 'tcp_options',
             'tcp_seq', 'tcp_timestamp', 'tcp_timestamp_echo_reply', 'tcp_urp',
             'tcp_window_scaling', 'tcp_window_size']
more = ['os_name', 'os_version']

print('unique ip_ttl', df['ip_ttl'].nunique())
print('unique tcp_options', df['tcp_options'].nunique())
print(df['tcp_options'].value_counts())
print(df['os_name'].value_counts())
print(df['tcp_window_size'].value_counts())
print(df['ip_ttl'].value_counts())

dbList = []
databaseFile = 'data.json'
with open(databaseFile) as f:
    dbList = json.load(f)


def get_score(fp, dbList):
    scores = []
    for i, entry in enumerate(dbList):
        score = 0
        if compute_ip_id(entry['ip_id']) == compute_ip_id(fp['ip_id']):
            score += 1
        if compute_near_ttl(entry['ip_ttl']) == compute_near_ttl(fp['ip_ttl']):
            score += 1
        for key in remaining:
            if fp[key] == entry[key]:
                score += 1
        scores.append({
            'os_name': entry['os_name'],
            'score': score,
        })

    avg_score_os_class = {
        "Android": 0,
        "Linux":  0,
        "Mac OS":  0,
        "Windows":  0,
        "iOS": 0,
    }

    os_count = {
        "Android": 0,
        "Linux":  0,
        "Mac OS":  0,
        "Windows":  0,
        "iOS": 0,
    }

    for score in scores:
        avg_score_os_class[score['os_name']] += score['score']
        os_count[score['os_name']] += 1

    for os in avg_score_os_class:
        avg_score_os_class[os] = round(
            avg_score_os_class[os] / os_count[os], 1)

    return avg_score_os_class


def compute_ip_id(ip_id):
    if ip_id == 0:
        return 0
    else:
        return 1


def compute_near_ttl(ip_ttl):
    guessed_ttl_start = ip_ttl

    if ip_ttl > 0 and ip_ttl <= 32:
        guessed_ttl_start = 32
    elif ip_ttl > 32 and ip_ttl <= 64:
        guessed_ttl_start = 64
    elif ip_ttl > 64 and ip_ttl <= 128:
        guessed_ttl_start = 128
    elif ip_ttl > 128:
        guessed_ttl_start = 255

    return guessed_ttl_start


for i, entry in enumerate(dbList):
    score = get_score(entry, dbList)
    highest = max(score, key=score.get)
    if entry['os_name'] != highest:
        print(entry['os_name'], highest, score)
