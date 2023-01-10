import json
from tcpip_fp_logging import log

databaseFile = './database/January2023Cleaned.json'
dbList = []

# load fingerprints into database
with open(databaseFile) as f:
    dbList = json.load(f)
log('Loaded {} fingerprints from the database'.format(
    len(dbList)), 'tcp_fingerprint')

def computeNearTTL(ip_ttl):
    guessed_ttl_start = ip_ttl

    if ip_ttl > 0 and ip_ttl <= 16:
        guessed_ttl_start = 16
    elif ip_ttl > 16 and ip_ttl <= 32:
        guessed_ttl_start = 32
    elif ip_ttl > 32 and ip_ttl <= 60:
        guessed_ttl_start = 60  # unlikely to find many of these anymore
    elif ip_ttl > 60 and ip_ttl <= 64:
        guessed_ttl_start = 64
    elif ip_ttl > 64 and ip_ttl <= 128:
        guessed_ttl_start = 128
    elif ip_ttl > 128:
        guessed_ttl_start = 255

    return guessed_ttl_start


def makeOsGuess(fp, n=3):
    """
    Return the highest scoring TCP/IP fingerprinting match from the database.
    If there is more than one highest scoring match, return all the highest scoring matches.

    As a second guess, output the operating system with the highest, normalized average score.
    """
    perfectScore = 11.5
    scores = []
    for i, entry in enumerate(dbList):
        score = 0
        # @TODO: consider `ip_tll`
        if computeNearTTL(entry['ip_ttl']) == computeNearTTL(fp['ip_ttl']):
            score += 1.5
        # @TODO: consider `tcp_window_scaling`
        # check IP DF bit
        if entry['ip_df'] == fp['ip_df']:
            score += 1
        # check IP MF bit
        if entry['ip_mf'] == fp['ip_mf']:
            score += 1
        # check TCP window size
        if entry['tcp_window_size'] == fp['tcp_window_size']:
            score += 1.5
        # check TCP flags
        if entry['tcp_flags'] == fp['tcp_flags']:
            score += 1
        # check TCP header length
        if entry['tcp_header_length'] == fp['tcp_header_length']:
            score += 1
        # check TCP MSS
        if entry['tcp_mss'] == fp['tcp_mss']:
            score += 1.5
        # check TCP options
        if entry['tcp_options'] == fp['tcp_options']:
            score += 3
        else:
            # check order of TCP options (this is weaker than TCP options equality)
            orderEntry = ''.join(
                [e[0] for e in entry['tcp_options'].split(',') if e])
            orderFp = ''.join([e[0]
                              for e in fp['tcp_options'].split(',') if e])
            if orderEntry == orderFp:
                score += 2

        scores.append({
            'i': i,
            'score': score,
            'os': entry.get('os', {}).get('name'),
        })

    # Return the highest scoring TCP/IP fingerprinting match
    scores.sort(key=lambda x: x['score'], reverse=True)
    guesses = []
    highest_score = scores[0].get('score')
    for guess in scores:
        if guess['score'] != highest_score:
            break
        guesses.append({
            'score': '{}/{}'.format(guess['score'], perfectScore),
            'os': guess['os'],
        })

    # get the os with the highest, normalized average score
    os_score = {}
    for guess in scores:
        if guess['os']:
            if not os_score.get(guess['os']):
                os_score[guess['os']] = []
            os_score[guess['os']].append(guess['score'])

    highest_os_avg = 0
    highest_os = None
    avg_os_score = {}
    for key in os_score:
        N = len(os_score[key])
        # only consider OS classes with at least 8 elements
        if N >= 8:
            avg = sum(os_score[key]) / N
            avg_os_score[key] = 'avg={}, N={}'.format(round(avg, 2), N)
            if avg >= highest_os_avg:
                highest_os = key
            highest_os_avg = max(avg, highest_os_avg)

    return {
        'best_n_guesses': guesses[:n],
        'avg_score_os_class': avg_os_score,
        'fp': fp,
        'details': {
          'os_highest_class': highest_os,
          'perfect_score': perfectScore,
        }
    }