const fs = require('fs')

let data = JSON.parse(fs.readFileSync('January2023.json'))
let newData = [];

// "avg_score_os_class": {
//   "Android": "avg=6.07, N=2501",
//   "HarmonyOS": "avg=6.68, N=11",
//   "Linux": "avg=5.1, N=1149",
//   "Mac OS": "avg=10.08, N=2501",
//   "Ubuntu": "avg=5.08, N=200",
//   "Windows": "avg=3.71, N=2501",
//   "iOS": "avg=8.46, N=2501"
// },

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

fs.writeFileSync('January2023Cleaned.json', JSON.stringify(newData, null, 2))