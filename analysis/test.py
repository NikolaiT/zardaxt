import json
import math
import random

clusters = ["Android", "Linux", "Mac OS", "Windows", "iOS"]
all_keys = ['ip_checksum', 'ip_df', 'ip_hdr_length', 'ip_id',
            'ip_mf', 'ip_off', 'ip_protocol', 'ip_rf', 'ip_tos',
            'ip_total_length', 'ip_ttl', 'ip_version', 'tcp_ack', 'tcp_checksum',
            'tcp_flags', 'tcp_header_length', 'tcp_mss', 'tcp_off', 'tcp_options',
            'tcp_seq', 'tcp_timestamp', 'tcp_timestamp_echo_reply', 'tcp_urp',
            'tcp_window_scaling', 'tcp_window_size']


def gos(os_name):
    """
    Unix-Like: Android and Linux
    Apple-Like: iOS and Mac OS

    Args:
        os_name (str): The detailed operating system

    Returns:
        str: The clustered operating system
    """
    if os_name in ["Android", "Linux"]:
        return 'Unix-Like'
    if os_name in ["Mac OS", "iOS"]:
        return 'Apple-Like'
    return os_name


def get_score(fp, dbList, ignoreKey=None):
    score_os_class = {
        'Unix-Like':  {'score': 0, 'total': 0},
        'Apple-Like':  {'score': 0, 'total': 0},
        "Windows":  {'score': 0, 'total': 0},
    }
    for entry in dbList:
        score = 0
        if ignoreKey != 'ip_id':
            if compute_ip_id(entry['ip_id']) == compute_ip_id(fp['ip_id']):
                score += 1
        if ignoreKey != 'ip_ttl':
            if compute_near_ttl(entry['ip_ttl']) == compute_near_ttl(fp['ip_ttl']):
                score += 1
        for key in all_keys:
            if key != 'ip_id' and key != 'ip_ttl':
                if ignoreKey != key and fp[key] == entry[key]:
                    score += 1

        _os = gos(entry['os_name'])
        score_os_class[_os]['score'] += score
        score_os_class[_os]['total'] += 1

    avg_score_os_class = {
        'Unix-Like': 0,
        'Apple-Like':  0,
        "Windows":  0,
    }

    for os in score_os_class:
        avg_score_os_class[os] = round(
            score_os_class[os]['score'] / score_os_class[os]['total'], 1)

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


def get_learning_data(data, threshold=.8):
    num_training = math.floor(len(data) * threshold)
    # we have the same amount of data for each class
    # just shuffle, this will be good enough
    # {'Android': 2501, 'Linux': 2501, 'Mac OS': 2501, 'Windows': 2501, 'iOS': 2501}
    random.shuffle(data)
    return data[: num_training], data[num_training:]


def get_dist(os, scores):
    dist = 0
    num = 0
    for key in scores:
        if key != os:
            dist += scores[key] / scores[os]
            num += 1
    return dist / num


def get_miss_rate(training, testing, ignoreKey=None):
    avg_miss_rate = {}
    miss_rate = {}
    for entry in testing:
        os_name = gos(entry['os_name'])
        score = get_score(entry, training, ignoreKey=ignoreKey)
        highest_os = max(score, key=score.get)

        if not miss_rate.get(os_name):
            miss_rate[os_name] = {'miss': 0, 'dist': 0, 'total': 0}

        miss_rate[os_name]['total'] += 1

        if os_name != highest_os:
            miss_rate[os_name]['miss'] += 1

        # get the distance from the interfered OS
        # to all other OS'
        miss_rate[os_name]['dist'] += get_dist(highest_os, score)

    for os in miss_rate:
        _miss_rate = round(miss_rate[os]['miss'] /
                           miss_rate[os]['total'], 4)
        _avg_dist = round(miss_rate[os]['dist'] /
                          miss_rate[os]['total'], 4)
        avg_miss_rate[os] = {'miss_rate': _miss_rate, 'avg_dist': _avg_dist}

    return avg_miss_rate


def main():
    dbList = []
    databaseFile = 'data.json'
    with open(databaseFile) as f:
        dbList = json.load(f)

    random.shuffle(dbList)
    # dbList = dbList[:1000]
    training, testing = get_learning_data(dbList)
    print('num training: {}, num testing: {}'.format(len(training), len(testing)))

    base_miss_rate = get_miss_rate(training, testing)
    print('base_miss_rate', base_miss_rate)
    print()
    results = {
        'base_score': base_miss_rate,
    }
    for key in all_keys:
        miss_rate_toggle_field = get_miss_rate(
            training, testing, ignoreKey=key)
        results[key] = miss_rate_toggle_field
        print(key, miss_rate_toggle_field)
        with open('miss_rates.json', 'w') as fp:
            json.dump(results, fp, indent=2)

    for os in results['base_score'].keys():
        sort_by_dist = sorted(
            results.items(), key=lambda item: item[1][os]['avg_dist'], reverse=True)
        print(os)
        res = list(
            map(lambda item: (item[0], item[1][os]['avg_dist']), sort_by_dist))
        print(res)
        print()
        with open('res_{}.json'.format(os.replace(' ', '').strip()), 'w') as fp:
            json.dump(res, fp, indent=2)


main()
