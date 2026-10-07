const pool = require("./db");

async function main() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS people (
      id BIGSERIAL PRIMARY KEY,
      last_name TEXT,
      first_name TEXT,
      email TEXT,
      address TEXT,
      postal_code TEXT,
      city TEXT,
      birth_date TEXT,
      department TEXT,
      phone TEXT,
      source TEXT
    );

    ALTER TABLE people
      ADD COLUMN IF NOT EXISTS source TEXT;

    CREATE INDEX IF NOT EXISTS people_last_name_idx
      ON people (LOWER(last_name));

    CREATE INDEX IF NOT EXISTS people_first_name_idx
      ON people (LOWER(first_name));

    CREATE INDEX IF NOT EXISTS people_email_idx
      ON people (LOWER(email));

    CREATE INDEX IF NOT EXISTS people_phone_idx
      ON people (phone);

    CREATE INDEX IF NOT EXISTS people_postal_code_idx
      ON people (postal_code);

    CREATE INDEX IF NOT EXISTS people_source_idx
      ON people (LOWER(source));
  `);

  console.log("Base FastSearch initialisée.");
  await pool.end();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
