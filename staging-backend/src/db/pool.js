import pg from 'pg';
import { config } from '../config.js';

// DB_SCHEMA is validated as a lowercase identifier before interpolation. A
// single-schema search_path deliberately excludes public and all other app schemas.
export function poolOptionsFor(databaseConfig) {
  return {
    connectionString: databaseConfig.DATABASE_URL,
    ssl: databaseConfig.DATABASE_SSL === 'true' ? { rejectUnauthorized: true } : undefined,
    max: 10,
    application_name: 'corvon-recovery-api',
    options: `-c search_path=${databaseConfig.DB_SCHEMA}`
  };
}

export const pool = new pg.Pool({
  ...poolOptionsFor(config)
});
export async function query(text, values) { return pool.query(text, values); }
