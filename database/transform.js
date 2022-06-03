const fs = require('fs')
const Bowser = require("bowser");

let db_file = 'db_june_2022.json';
let data = JSON.parse(fs.readFileSync(db_file))
let newData = [];

for (let key in data.obj) {
  let entry = data.obj[key];
  let new_entry = Object.assign({}, entry.tcpip_fp.fp);

  if (entry.userAgent) {
    let parsed = Bowser.parse(entry.userAgent);
    console.log(parsed);
    new_entry.userAgent = entry.userAgent;
    new_entry.os = parsed.os;
    new_entry.platform = parsed.platform;
  }
  delete new_entry.src_ip;
  delete new_entry.src_port;
  delete new_entry.dst_ip;
  delete new_entry.dst_port;
  newData.push(new_entry)
}

fs.writeFileSync('combinedJune2022.json', JSON.stringify(newData, null, 2))