const fs = require('fs')

let data = JSON.parse(fs.readFileSync('db_june_2022.json'))
console.log(Object.keys(data.obj).length)
