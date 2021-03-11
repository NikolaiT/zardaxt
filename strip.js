const fs = require('fs')

let data = JSON.parse(fs.readFileSync('database.json'))
let newData = [];

for (let entry of data) {
  delete entry.src_ip;
  delete entry.dst_ip;
  delete entry.dst_port;
  newData.push(entry)
}

fs.writeFileSync('database.json', JSON.stringify(newData, null, 2))