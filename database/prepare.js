const fs = require('fs');
const crypto = require('crypto');

const getTcpTimestamp = (tcp_ts) => {
  return tcp_ts == "" ? 0 : 1;
}

const getIpId = (ip_id) => {
  return ip_id == 0 ? 0 : 1;
}

const getNearTTL = (ip_ttl) => {
  let guessed = ip_ttl;

  if (ip_ttl >= 0 && ip_ttl <= 32) {
    guessed = 32;
  } else if (ip_ttl > 32 && ip_ttl <= 64) {
    guessed = 64
  } else if (ip_ttl > 64 && ip_ttl <= 128) {
    guessed = 128
  } else if (ip_ttl > 128) {
    guessed = 255
  }

  return guessed
}

const createNewDatabase = () => {
  const files = process.argv.slice(2);
  if (files.length === 0) {
    console.error('usage: node prepare.js <labelled fingerprints .json>...');
    process.exit(1);
  }
  let data = [];
  for (const file of files) {
    console.log(`Reading ${file}`);
    data = data.concat(JSON.parse(fs.readFileSync(file)));
  }
  // One entry per distinct (normalized fingerprint, OS); `n` counts the sessions
  // that produced it, so fingerprint.py can weight common stacks over one-offs.
  let newData = [];
  const byHash = {};
  // Android and Chrome OS are Linux: same kernel, same SYN (src/fingerprint.py, OS_CLASSES).
  const LINUX = ['Android', 'HarmonyOS', 'Chromium OS', 'ChromeOS', 'Ubuntu', 'Debian', 'Fedora'];
  const allowedOS = ['Linux', 'Mac OS', 'Windows', 'iOS'];
  let osDist = {};
  let N = data.length;
  for (let entry of data) {
    const osName = entry.userAgentParsed.os.name;
    if (!osDist[osName]) {
      osDist[osName] = 0;
    }
    osDist[osName]++;
    const fp = entry.info.fp;
    const os = LINUX.includes(osName) ? 'Linux' : osName;
    if (allowedOS.includes(os)) {
      const entropy = {
        "tcp_options": fp["tcp_options"],
        "tcp_options_ordered": fp["tcp_options"].split(',').map(el => el[0]).filter(e => !!e).join(''),
        "ip_total_length": fp["ip_total_length"],
        "tcp_off": fp["tcp_off"],
        "tcp_window_scaling": fp["tcp_window_scaling"],
        "tcp_window_size": fp["tcp_window_size"],
        "ip_ttl": getNearTTL(fp["ip_ttl"]),
        "ip_id": getIpId(fp["ip_id"]),
        "tcp_timestamp": getTcpTimestamp(fp["tcp_timestamp"]),
        "tcp_timestamp_echo_reply": getTcpTimestamp(fp["tcp_timestamp_echo_reply"]),
        "tcp_mss": fp["tcp_mss"],
        "tcp_flags": fp["tcp_flags"],
        "ip_tos": fp["ip_tos"],
        "os": os
      };
      const entropyHash = crypto.createHash('sha1').update(JSON.stringify(entropy)).digest('hex');
      if (byHash[entropyHash]) {
        byHash[entropyHash].n++;
      } else {
        entropy.n = 1;
        byHash[entropyHash] = entropy;
        newData.push(entropy);
      }
    }
  }
  const perOs = {};
  for (const e of newData) perOs[e.os] = (perOs[e.os] || 0) + 1;
  console.log('osDist', osDist);
  console.log(`N=${N}, distinct fingerprints=${newData.length}`, perOs);
  fs.writeFileSync('newCleaned.json', JSON.stringify(newData, null, 2));
};

createNewDatabase();
