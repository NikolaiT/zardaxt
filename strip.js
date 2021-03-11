const fs = require('fs')

let data = JSON.parse(fs.readFileSync('database.json'))

for (let entry of data) {
  delete entry.src_ip;
  delete entry.dst_ip;
  delete entry.dst_port;
}

fs.writeFileSync('databaseC.json', JSON.stringify(data, null, 2))