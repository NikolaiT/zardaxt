import math
import json
import random


def get_data():
    data = []
    databaseFile = 'rawData.json'
    with open(databaseFile) as f:
        data = json.load(f)
        print(f'Loaded {len(data)} fingerprints')
    return data


def load_database():
    with open('./../database/database.json') as f:
        return json.load(f)


def score_fp(fp, fpList, use_ip_total_length=False, use_tcp_off=False):
    os_scores = {
        'Android': 0,
        'Windows': 0,
        'Mac OS': 0,
        'iOS': 0,
        'Linux': 0,
        'Chromium OS': 0,
    }
    os_sample_count = {
        'Android': 0,
        'Windows': 0,
        'Mac OS': 0,
        'iOS': 0,
        'Linux': 0,
        'Chromium OS': 0,
    }
    for entry in fpList:
        score = 0
        os_name = entry['os']
        if entry['ip_id'] == fp['ip_id']:
            score += 1.5
        if entry['ip_tos'] == fp['ip_tos']:
            score += 0.25
        if use_ip_total_length:
            if entry['ip_total_length'] == fp['ip_total_length']:
                score += 2.5
        if entry['ip_ttl'] == fp['ip_ttl']:
            score += 2
        if use_tcp_off:
            if entry['tcp_off'] == fp['tcp_off']:
                score += 2.5
        if entry['tcp_timestamp_echo_reply'] == fp['tcp_timestamp_echo_reply']:
            score += 2
        if entry['tcp_window_scaling'] == fp['tcp_window_scaling']:
            score += 2
        if entry['tcp_window_size'] == fp['tcp_window_size']:
            score += 2
        if entry['tcp_flags'] == fp['tcp_flags']:
            score += 0.25
        if entry['tcp_mss'] == fp['tcp_mss']:
            score += 1.5
        if entry['tcp_options'] == fp['tcp_options']:
            score += 4
        elif entry['tcp_options_ordered'] == fp['tcp_options_ordered']:
            score += 2.5
        os_scores[os_name] += score
        os_sample_count[os_name] += 1

    avg_os_score = {}
    for os_name in os_scores:
        avg_os_score[os_name] = round(
            os_scores[os_name] / os_sample_count[os_name], 2)

    return avg_os_score


def get_learning_data(data, threshold=.8):
    num_training = math.floor(len(data) * threshold)
    random.shuffle(data)
    return data[: num_training], data[num_training:]


def same_os(os1, os2):
    apple = ['iOS', 'Mac OS']
    linux = ['Linux', 'Chromium OS']

    if os1 == os2:
        return True

    if os1 in apple and os2 in apple:
        return True

    if os1 in linux and os2 in linux:
        return True

    return False


def main():
    """
    With ip_total_length and tcp_off: Ratio of correctly classified: 3349/76732
    Without ip_total_length and tcp_off: Ratio of correctly classified: 2484/77597
    """
    db = load_database()
    data = get_data()
    training, testing = get_learning_data(data, threshold=0.8)
    numFalse = 0
    numCorrect = 0
    for fp in testing:
        score = score_fp(fp, db, use_ip_total_length=False, use_tcp_off=False)
        highest_os = max(score, key=score.get)
        same = same_os(highest_os, fp['os'])
        if not same:
            numFalse += 1
            print(fp['os'], highest_os, same)
        else:
            numCorrect += 1
    print(f'Ratio of correctly classified: {numFalse}/{numCorrect}')


main()
