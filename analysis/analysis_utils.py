import json


def get_data():
    data = []
    databaseFile = 'data.json'
    with open(databaseFile) as f:
        data = json.load(f)
    return data


def gos(os_name, reduce_classes=True):
    """
    Unix-Like: Android and Linux
    Apple-Like: iOS and Mac OS

    Args:
        os_name (str): The detailed operating system

    Returns:
        str: The clustered operating system
    """
    if reduce_classes:
        if os_name in ["Android", "Linux"]:
            return 'Unix-Like'
        if os_name in ["Mac OS", "iOS"]:
            return 'Apple-Like'
    return os_name


def get_var_value(var, entry, assume_ttl=False):
    value = entry[var]
    if var == 'ip_id':
        value = compute_ip_id(entry['ip_id'])
    if assume_ttl and var == 'ip_ttl':
        value = compute_near_ttl(entry['ip_ttl'])
    if var == 'tcp_timestamp':
        value = compute_tcp_timestamp(entry['tcp_timestamp'])
    return value


def compute_tcp_timestamp(tcp_timestamp):
    if isinstance(tcp_timestamp, int) and tcp_timestamp > 0:
        return 1
    elif tcp_timestamp == '':
        return 0
    else:
        raise Exception(
            'Invalid tcp_timestamp value: {}'.format(tcp_timestamp))


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


def create_hist():
    histogram = {}
    data = get_data()
    for fp in data:
        value = fp['ip_total_length']
        _os = gos(fp['os_name'])
        if not histogram.get(_os):
            histogram[_os] = {}
        if not histogram[_os].get(value, False):
            histogram[_os][value] = 0
        histogram[_os][value] += 1

    with open('./data/ip_total_length.json', 'w') as fp:
        json.dump(histogram, fp, indent=2)


if __name__ == '__main__':
    create_hist()
