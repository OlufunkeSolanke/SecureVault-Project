const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const path = require('path');
const fs = require('fs');

const dbDir = path.join(__dirname, '../../data');
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const adapter = new FileSync(path.join(dbDir, 'securevault.json'));
const db = low(adapter);

function initDB() {
  db.defaults({
    users: [],
    notes: [],
    audit_logs: []
  }).write();
  console.log('[DB] Database initialised at data/securevault.json');
}

module.exports = { db, initDB };
