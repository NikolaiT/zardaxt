const fs = require('fs')

const db_file = 'combined.json';
let data = JSON.parse(fs.readFileSync(db_file))

let count = {};

for (let entry of data) {
  if (entry.os) {
    if (!count[entry.os.name]) {
      count[entry.os.name] = 0;
    }
    count[entry.os.name]++;
  }
}

console.log(count);