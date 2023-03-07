from analysis_utils import get_var_value, get_data


def construct_new_fingerprint(fp):
    fp_str = '3-4-{}-{}-{}-{}-{}-{}-{}'.format(
        fp['ip_total_length'],
        fp['tcp_off'],
        fp['tcp_window_size'],
        get_var_value('ip_ttl', fp),
        get_var_value('ip_id', fp),
        get_var_value('tcp_timestamp', fp),
        fp['tcp_options'],
    )
    return fp_str


def main():
    printable = []
    hist = {}
    data = get_data()
    print('Total fingerprints in database: {}'.format(len(data)))
    for fp in data:
        fp_str = construct_new_fingerprint(fp)
        if not hist.get(fp_str):
            hist[fp_str] = 0
        hist[fp_str] += 1
        printable.append(
            '{} {} {}'.format(fp.get('os_name', ''), fp.get('os_version', ''), fp_str))

    with open('fingerprints.txt', 'w') as fp:
        fp.write('\n'.join(printable))

    print('Num unique fingerprints in database: {}'.format(len(hist)))


main()
