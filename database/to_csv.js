const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const fs = require('fs');

const includeUserAgent = false;
const fields = ['ip_checksum', 'ip_df', 'ip_hdr_length',
  'ip_id', 'ip_mf', 'ip_off', 'ip_protocol', 'ip_rf', 'ip_tos',
  'ip_total_length', 'ip_ttl', 'ip_version', 'tcp_ack', 'tcp_checksum',
  'tcp_flags', 'tcp_header_length', 'tcp_mss', 'tcp_off', 'tcp_options',
  'tcp_seq', 'tcp_timestamp', 'tcp_timestamp_echo_reply', 'tcp_urp',
  'tcp_window_scaling', 'tcp_window_size'];

let header = [
  { id: 'os_name', title: 'os_name' },
  { id: 'os_version', title: 'os_version' },
];

if (includeUserAgent) {
  header.push({ id: 'user_agent', title: 'user_agent' });
}

for (let f of fields) {
  header.push({ id: f, title: f });
}

const csvWriter = createCsvWriter({
  path: 'tcp_ip.csv',
  header: header
});

let data = require('./February2023Cleaned.json');
let records = [];

for (let obj of data) {
  let d = {
    os_name: obj.userAgentParsed.os.name,
    os_version: obj.userAgentParsed.os.version,
  };
  if (includeUserAgent) {
    d.user_agent = obj.userAgentParsed.ua;
  }
  for (let f of fields) {
    d[f] = obj[f];
  }
  records.push(d);
}

fs.writeFileSync('../analysis/data.json', JSON.stringify(records, null, 2));

csvWriter.writeRecords(records)
  .then(() => {
    console.log('...Done');
  });