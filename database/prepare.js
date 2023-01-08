const fs = require('fs')

let data = JSON.parse(fs.readFileSync('January2023.json'))
let newData = [];

for (let entry of data) {
  let new_entry = Object.assign({}, entry.details.fp);
  new_entry.os = entry.os;
  new_entry.platform = entry.platform;
  new_entry.userAgent = entry.userAgent;
  // delete new_entry.uptime_interpolation;
  delete new_entry.src_ip;
  delete new_entry.src_port;
  delete new_entry.dst_ip;
  delete new_entry.dst_port;
  newData.push(new_entry)
}

fs.writeFileSync('January2023Cleaned.json', JSON.stringify(newData, null, 2))