'use strict';

const path = require('node:path');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const {
    DEFAULT_BENCHMARK_EMAIL,
    assertDedicatedBenchmarkEmail
} = require('./benchmarkUtils');

async function prepareBenchmarkUser() {
    require('dotenv').config({
        path: path.resolve(__dirname, '../../.env'),
        quiet: true
    });
    require('dotenv').config({
        path: path.resolve(__dirname, '../.env'),
        quiet: true
    });
    const email = assertDedicatedBenchmarkEmail(
        process.env.BENCHMARK_USER_EMAIL || DEFAULT_BENCHMARK_EMAIL
    );
    const password = process.env.BENCHMARK_USER_PASSWORD;
    if (typeof password !== 'string' || password.length < 16) {
        throw new Error('Set BENCHMARK_USER_PASSWORD to a temporary password of at least 16 characters.');
    }

    const pool = new Pool({
        host: process.env.DB_HOST,
        port: Number(process.env.DB_PORT),
        database: process.env.DB_NAME,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD
    });
    try {
        const passwordHash = await bcrypt.hash(password, 12);
        const inserted = await pool.query(
            `INSERT INTO users (email, password_hash, role)
             VALUES ($1, $2, 'user')
             ON CONFLICT (email) DO NOTHING
             RETURNING id`,
            [email, passwordHash]
        );
        if (inserted.rows.length !== 1) {
            throw new Error('The dedicated benchmark user already exists; no account was changed.');
        }
        return { id: String(inserted.rows[0].id), email };
    } finally {
        await pool.end();
    }
}

if (require.main === module) {
    prepareBenchmarkUser()
        .then((user) => {
            console.log(JSON.stringify(user));
        })
        .catch((error) => {
            console.error('[Benchmark] User preparation failed:', error.code || error.name);
            process.exitCode = 1;
        });
}

module.exports = { prepareBenchmarkUser };
