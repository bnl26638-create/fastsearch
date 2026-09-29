const fs = require("fs");
const { parse } = require("csv-parse");
const pool = require("./db");

const FILE = process.argv[2];

if (!FILE) {
  console.error("Utilisation : node import-data.js sfr10k.txt");
  process.exit(1);
}

async function main() {
  const client = await pool.connect();

  let count = 0;

  try {
    await client.query("BEGIN");

    const parser = fs
      .createReadStream(FILE)
      .pipe(
        parse({
          delimiter: ",",
          quote: '"',
          relax_quotes: true,
          relax_column_count: true,
          skip_empty_lines: true
        })
      );

    for await (const row of parser) {
      if (row.length < 9) continue;

      const [
        lastName,
        firstName,
        email,
        address,
        postalCode,
        city,
        birthDate,
        department,
        phone
      ] = row;

      await client.query(
        `
        INSERT INTO people
        (last_name, first_name, email, address, postal_code,
         city, birth_date, department, phone)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        `,
        [
          lastName || null,
          firstName || null,
          email || null,
          address || null,
          postalCode || null,
          city || null,
          birthDate || null,
          department || null,
          phone || null
        ]
      );

      count++;

      if (count % 1000 === 0) {
        console.log(`${count} lignes importées...`);
      }
    }

    await client.query("COMMIT");

    console.log(`Import terminé : ${count} lignes.`);
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch(err => {
  console.error("Erreur import :", err);
  process.exit(1);
});
