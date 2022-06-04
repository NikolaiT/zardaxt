const fs = require('fs')

let data = JSON.parse(fs.readFileSync('combinedJune2022.json'))

let ttl = {};

for (let entry of data) {
  if (entry.os) {
    if (!ttl[entry.ip_ttl]) {
      ttl[entry.ip_ttl] = [];
    }
    ttl[entry.ip_ttl].push(entry.os.name);
  }
}

console.log(ttl);