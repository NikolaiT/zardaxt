const fs = require('fs');

function sortObjectByValue(obj) {
  if (obj && typeof obj === 'object') {
    let entries = Object.entries(obj);
    let sorted = entries.sort((a, b) => {
      return b[1] - a[1];
    });
    let newObj = {};
    for (let [key, value] of sorted) {
      newObj[key] = value;
    }
    return newObj;
  }
  return obj;
}

function tcpIpFingerprintHistogram() {
  let hist = {};
  let data = require('./data.json');
  for (let tcpip_fp of data) {
    for (let key of Object.keys(tcpip_fp)) {
      let value = tcpip_fp[key];
      if (!hist[key]) {
        hist[key] = {};
      }
      if (!hist[key][value]) {
        hist[key][value] = 0;
      }
      hist[key][value]++;
    }
  }
  for (let cat in hist) {
    hist[cat] = sortObjectByValue(hist[cat]);
  }
  fs.writeFileSync(`hist.json`, JSON.stringify(hist, null, 2));
}

tcpIpFingerprintHistogram();