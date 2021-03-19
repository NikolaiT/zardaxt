const fs = require('fs')

for (let db_file of ['database1.json', 'database2.json', 'database3.json', 'combined.json']) {
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
  console.log(db_file, count);
}