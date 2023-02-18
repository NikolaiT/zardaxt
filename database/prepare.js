const fs = require('fs')

let data = JSON.parse(fs.readFileSync('February2023.json'))
let newData = [];

const allowedOS = ['Android', 'Linux', 'Mac OS', 'Windows', 'iOS'];

for (let entry of data) {
  let new_entry = Object.assign({}, entry.details.fp);
  new_entry.userAgentParsed = entry.userAgentParsed;
  delete new_entry.src_ip;
  delete new_entry.src_port;
  delete new_entry.dst_ip;
  delete new_entry.dst_port;
  if (allowedOS.includes(entry.userAgentParsed.os.name)) {
    newData.push(new_entry)
  }
}

fs.writeFileSync('February2023Cleaned.json', JSON.stringify(newData, null, 2))