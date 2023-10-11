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
  let data1 = JSON.parse(fs.readFileSync('July2023-de.json'));
  let data2 = JSON.parse(fs.readFileSync('July2023-us.json'));
  let data3 = JSON.parse(fs.readFileSync('August2023-de.json'));
  // October 2023
  let data6 = JSON.parse(fs.readFileSync('October2023-de.json'));
  let data7 = JSON.parse(fs.readFileSync('October2023-us.json'));
  let data8 = JSON.parse(fs.readFileSync('OctoberSecond2023-us.json'));

  let data = data1;
  data = data.concat(data2);
  data = data.concat(data3);
  data = data.concat(data6);
  data = data.concat(data7);
  data = data.concat(data8);

  let newData = [];
  let duplicates = [];
  const allowedOS = ['Android', 'Linux', 'Mac OS', 'Windows', 'iOS'];
  let entropyDict = {
    'Android': [],
    'Linux': [],
    'Mac OS': [],
    'Windows': [],
    'iOS': [],
  };
  let N = data.length;
  let newEntropyCount = 0;
  let noEntropyCount = 0;
  for (let entry of data) {
    const fp = entry.info.fp;
    if (allowedOS.includes(entry.userAgentParsed.os.name)) {
      let os = entry.userAgentParsed.os.name;
      if (['Ubuntu', 'Debian'].includes(os)) {
        os = 'Linux';
      }
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
      const shasum = crypto.createHash('sha1');
      shasum.update(JSON.stringify(entropy));
      const entropyHash = shasum.digest('hex');
      if (entropyDict[os].includes(entropyHash)) {
        noEntropyCount++;
        duplicates.push(entropy);
      } else {
        newEntropyCount++;
        entropyDict[os].push(entropyHash);
        newData.push(entropy);
      }
    }
  }
  console.log(`N=${N}, newEntropyCount=${newEntropyCount}, noEntropyCount=${noEntropyCount}`);
  console.log(Object.entries(entropyDict).map((el) => [el[0], el[1].length]));
  fs.writeFileSync('newCleaned.json', JSON.stringify(newData, null, 2));
  fs.writeFileSync('duplicates.json', JSON.stringify(duplicates, null, 2));
};


/**
 * N=12510, newEntropyCount=1031, noEntropyCount=11474
[
  [ 'Android', 184 ],
  [ 'Linux', 242 ],
  [ 'Mac OS', 194 ],
  [ 'Windows', 153 ],
  [ 'iOS', 258 ]
]
 */

createNewDatabase();
