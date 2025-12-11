import sqlite3 from "sqlite3";

const db = new sqlite3.Database("./database.db"); // senin DB dosyan

db.run(`DELETE FROM users`, function(err) {
  if (err) return console.error(err.message);
  console.log(`Tüm kullanıcılar silindi.`);
  db.close();
});
