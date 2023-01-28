const fs = require('fs')

const files = [
  'January2023Cleaned.json'
];

for (let db_file of files) {
  let data = JSON.parse(fs.readFileSync(db_file))

  let count = { _total: 0 };

  for (let entry of data) {
    count._total++;
    if (entry.os) {
      if (!count[entry.os.name]) {
        count[entry.os.name] = 0;
      }
      count[entry.os.name]++;
    }
  }
  console.log(db_file, count);
}