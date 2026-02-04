# Mollu App

## Local development (API)

### Prerequisites
- Node.js 18+
- Docker (for PostgreSQL)

### Setup
```bash
cd infra
docker compose up -d

cd ../apps/api
npm install
```

Create an `.env` file in `apps/api` using `.env.example` as a template.

### Run the API
```bash
cd apps/api
npm run start:dev
```

The API runs on `http://localhost:3000` with a global prefix of `/api`.

### Auth flow notes (JWT + refresh cookie)
- `POST /api/auth/login` returns an access token in JSON and sets a **HttpOnly** refresh cookie.
- `POST /api/auth/refresh` uses that cookie to rotate refresh tokens.
- `POST /api/auth/logout` revokes the refresh session and clears the cookie.

To test cookies in a browser, call the endpoints from a frontend on a different port and ensure CORS credentials are enabled. For CLI tools like `curl`, use `-c`/`-b` to persist cookies.

### Manual auth test checklist
1. **Signup**: `POST /api/auth/signup` with `{ email, password, nickname? }`.
2. **Login**: `POST /api/auth/login` and confirm the `refresh_token` cookie is set.
3. **Me**: `GET /api/auth/me` with `Authorization: Bearer <accessToken>`.
4. **Refresh**: `POST /api/auth/refresh` using the cookie; confirm a new access token is returned.
5. **Logout**: `POST /api/auth/logout`, then retry `/api/auth/refresh` and expect failure.
