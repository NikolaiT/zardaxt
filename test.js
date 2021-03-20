const fs = require('fs')

let data = JSON.parse(fs.readFileSync('classify.json'))
console.log(Object.keys(data).length)