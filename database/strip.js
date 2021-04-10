const fs = require('fs')
const Bowser = require("bowser");

const db_file = 'database4.json';
let data = JSON.parse(fs.readFileSync(db_file))
let newData = [];

for (let entry of data) {
  if (entry.navigatorUserAgent) {
    let parsed = Bowser.parse(entry.navigatorUserAgent);
    console.log(parsed);
    entry.os = parsed.os;
    entry.platform = parsed.platform;
  }
  delete entry.parsedUA;
  delete entry.src_ip;
  delete entry.dst_ip;
  delete entry.dst_port;
  newData.push(entry)
}

fs.writeFileSync(db_file, JSON.stringify(newData, null, 2))