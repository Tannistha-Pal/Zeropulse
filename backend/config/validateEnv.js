'use strict';

const REQUIRED_VALUES = [
    'JWT_SECRET',
    'DB_HOST',
    'DB_PORT',
    'DB_NAME',
    'DB_USER',
    'DB_PASSWORD',
    'REDIS_HOST',
    'REDIS_PORT'
];

const PLACEHOLDER_SECRET = /^(?:secret|changeme|change-me|password|default|your[-_ ]?(?:jwt[-_ ]?)?secret|replace[-_ ]with.*|development[-_ ]secret|test[-_ ]secret)$/i;

function parsePort(name, value, errors) {
    if (typeof value !== 'string' || !/^\d+$/.test(value)) {
        errors.push(`${name} must be an integer between 1 and 65535.`);
        return null;
    }

    const port = Number(value);
    if (port < 1 || port > 65535) {
        errors.push(`${name} must be an integer between 1 and 65535.`);
        return null;
    }

    return port;
}

function validateEnv(env = process.env) {
    const errors = [];
    for (const name of REQUIRED_VALUES) {
        if (typeof env[name] !== 'string' || !env[name].trim()) {
            errors.push(`${name} is required.`);
        }
    }

    const dbPort = env.DB_PORT ? parsePort('DB_PORT', env.DB_PORT, errors) : null;
    const redisPort = env.REDIS_PORT
        ? parsePort('REDIS_PORT', env.REDIS_PORT, errors)
        : null;
    const port = env.PORT === undefined
        ? 5000
        : parsePort('PORT', env.PORT, errors);

    if (
        env.NODE_ENV === 'production' &&
        typeof env.JWT_SECRET === 'string' &&
        (
            env.JWT_SECRET.length < 32 ||
            PLACEHOLDER_SECRET.test(env.JWT_SECRET.trim()) ||
            /^(.)\1+$/.test(env.JWT_SECRET)
        )
    ) {
        errors.push('JWT_SECRET must be a non-placeholder secret of at least 32 characters in production.');
    }

    const frontendOrigin = env.FRONTEND_ORIGIN || 'http://localhost:5173';
    try {
        const origin = new URL(frontendOrigin);
        if (
            !['http:', 'https:'].includes(origin.protocol) ||
            !origin.hostname ||
            origin.origin !== frontendOrigin
        ) {
            errors.push('FRONTEND_ORIGIN must be a valid HTTP or HTTPS origin without a path.');
        }
    } catch {
        errors.push('FRONTEND_ORIGIN must be a valid HTTP or HTTPS origin without a path.');
    }

    if (errors.length) {
        const error = new Error(`Invalid environment configuration: ${errors.join(' ')}`);
        error.name = 'EnvironmentValidationError';
        throw error;
    }

    return { port, dbPort, redisPort, frontendOrigin };
}

module.exports = { validateEnv };
