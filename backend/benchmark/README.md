# ZeroPulse API and CAEP Benchmarks

These opt-in benchmarks exercise the existing protected profile API and the real CAEP subscriber → risk engine → enforcement → Socket.IO path. They do not change risk decisions, bypass rate limits, or target ordinary user sessions.

## Requirements and isolation

- Docker Engine/Desktop with the Compose plugin.
- A running ZeroPulse Compose stack, configured from the repository-root `.env`.
- Use only the dedicated `zeropulse-benchmark@example.invalid` account. The `.invalid` top-level domain is reserved; the scripts reject other account names.
- API load testing requires an active login JWT for that dedicated account. The benchmark verifies its signature, PostgreSQL session, Redis session, and revocation state before sending requests. It deletes only that dedicated session when finished.
- Each CAEP trial creates a unique temporary session JTI and event ID, publishes one `TOKEN_HIJACKED` message through `caep:security_events`, and removes only its own session and Redis keys after checking the outcome. Never point benchmark configuration at a real user's account.

The default Docker Compose project remains the four application services. `docker-compose.benchmark.yml` adds a one-shot runner only when explicitly used.

## Prepare a dedicated account

Create the regular application stack and keep it running:

```powershell
docker compose up --build -d
```

Create one benchmark account. Provide a temporary password of at least 16 characters without saving it in `.env`:

```powershell
$secure = Read-Host "Temporary benchmark password" -AsSecureString
$passwordPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $env:BENCHMARK_USER_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPtr)
    $created = docker compose exec -T -e "BENCHMARK_USER_PASSWORD=$env:BENCHMARK_USER_PASSWORD" backend node benchmark/prepareBenchmarkUser.js
    $benchmarkUser = $created | ConvertFrom-Json
} finally {
    if ($passwordPtr -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPtr)
    }
    Remove-Item Env:BENCHMARK_USER_PASSWORD -ErrorAction SilentlyContinue
}
$benchmarkUser
```

The command prints the reserved email and generated database user ID, not the password. Set the ID for this PowerShell session, then login once to obtain a short-lived benchmark JWT:

```powershell
$env:BENCHMARK_USER_ID = $benchmarkUser.id
$env:BENCHMARK_USER_EMAIL = 'zeropulse-benchmark@example.invalid'
$secure = Read-Host "Temporary benchmark password" -AsSecureString
$passwordPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $env:BENCHMARK_USER_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPtr)
    $login = Invoke-RestMethod -Method Post `
        -Uri 'http://localhost:5173/api/auth/login' `
        -ContentType 'application/json' `
        -Body (@{ email = $env:BENCHMARK_USER_EMAIL; password = $env:BENCHMARK_USER_PASSWORD } | ConvertTo-Json)
    $env:BENCHMARK_JWT = $login.token
} finally {
    if ($passwordPtr -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPtr)
    }
    Remove-Item Env:BENCHMARK_USER_PASSWORD -ErrorAction SilentlyContinue
}
```

The Compose override reads benchmark values from the current shell first, then the root `.env`. Do not paste the JWT into a command argument or commit it; clear it from the shell when finished.

## Run the benchmarks in Docker

The API benchmark sends exactly 1,000 `GET /api/user/profile` requests by default, using concurrency 100. Requests go through the frontend Nginx `/api/` proxy. A 200 response is successful; 401, 429, 5xx, other HTTP statuses, and network errors are separately counted.

```powershell
docker compose -f docker-compose.yml -f docker-compose.benchmark.yml run --rm benchmark npm run benchmark:api -- --safe-report
```

The CAEP benchmark defaults to 20 distinct dedicated sessions and events:

```powershell
docker compose -f docker-compose.yml -f docker-compose.benchmark.yml run --rm benchmark npm run benchmark:revocation -- --safe-report
```

You can run between 20 and 50 trials with `--iterations`, for example `-- --iterations 50 --safe-report`. For the API benchmark, use `-- --requests 2000 --concurrency 50`, or set `BENCHMARK_REQUESTS=0` and `BENCHMARK_DURATION_SECONDS=60` for a 60-second run. The same values can be placed in the root `.env`; `.env.example` lists supported options.

The one-shot runner uses the existing `postgres`, `redis`, `backend`, and `frontend` services and waits for PostgreSQL and Redis healthchecks. The regular application stack is left running after the benchmark container exits.

## CAEP timing points

All short-interval measurements use `process.hrtime.bigint()`; wall-clock timestamps are not subtracted. The runner and backend should share a monotonic-clock domain, as they do in this Compose setup.

| Point | Meaning |
| --- | --- |
| T1 | Runner timestamp immediately before publishing the CAEP event to Redis. |
| T2 | Subscriber callback receives the event. |
| T3 | Risk evaluation completes. |
| T4 | Redis revocation key is written. |
| T5 | PostgreSQL session deactivation update completes. |
| T6 | Server emits the session-specific `session_revoked` Socket.IO event. |
| T7 | The authenticated Socket.IO benchmark client receives that event. |

Each successful trial reports event processing (T2−T1), risk evaluation (T3−T2), Redis enforcement (T4−T3), PostgreSQL deactivation (T5−T4), Socket.IO emission (T6−T5), end-to-end revocation (T6−T1), and client receipt (T7−T1). The client receipt is measured separately; a server-side Socket.IO emit is not treated as proof of delivery.

Every trial also requires the CAEP result to match its unique run/event/JTI, the Redis revocation key to exist, the PostgreSQL session to be inactive, the Socket.IO client to receive its session-specific notification, and a subsequent profile request with the revoked JWT to return 401. Failed trials remain in the report and are not counted as successful latency samples. Duplicate or mismatched results fail a trial rather than adding another success.

## Results and cleanup

- `backend/benchmark/results/` contains full, timestamped, environment-specific JSON and is ignored by Git. It can include account identifiers, origins, event IDs, and session JTIs; do not share it publicly.
- `backend/benchmark/reports/` contains the sanitized report generated with `--safe-report`. It includes per-trial success/failure and stage latencies, but omits JWTs, passwords, user/session/event IDs, and service origins; the report can be committed or shared.
- Neither output contains the benchmark JWT or password.
- The scripts clean each temporary CAEP session and its Redis keys. The API runner deletes only the dedicated login session it verified.
- Clear the shell JWT after use:

```powershell
Remove-Item Env:BENCHMARK_JWT -ErrorAction SilentlyContinue
Remove-Item Env:BENCHMARK_USER_ID -ErrorAction SilentlyContinue
Remove-Item Env:BENCHMARK_USER_EMAIL -ErrorAction SilentlyContinue
```

To run from a local `backend` checkout instead, install the normal backend dependencies and configure its existing `DB_*`, `REDIS_*`, and `JWT_SECRET` variables. Set `BENCHMARK_API_BASE_URL=http://localhost:5173` and `BENCHMARK_SOCKET_URL=http://localhost:5000` for host execution; API and revocation tests still require a dedicated account and an active local backend.
