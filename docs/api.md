# API Spec (v1)

## Auth
- POST /api/auth/signup
- POST /api/auth/login         -> returns accessToken, sets HttpOnly refresh cookie
- POST /api/auth/refresh       -> rotates refresh cookie, returns new accessToken
- POST /api/auth/logout        -> revokes refresh session + clears cookie
- GET  /api/auth/me            -> requires Bearer access token

### Auth flow
1. **Signup/Login**: receive an access token in JSON (and `Authorization` header). Refresh token is stored as HttpOnly cookie.
2. **Refresh**: call `/api/auth/refresh` with cookie; server rotates refresh token and returns a new access token. The refresh cookie is scoped to `/api/auth/refresh`.
3. **Logout**: call `/api/auth/logout` to revoke current refresh session.

## Groups
- POST /groups
- GET  /groups
- POST /groups/invite      -> returns inviteCode (or link)
- POST /groups/join        -> inviteCode
- GET  /groups/:groupId/members

## Expenses / Split
- POST /expenses           -> create expense (groupId, participants, mode, deadline)
- POST /expenses/:id/receipt   -> upload receipt image (mock OCR for MVP)
- GET  /expenses/:id/items
- PUT  /items/:itemId/shares    -> update member selections
- PUT  /expenses/:id/surcharges -> card/weekend surcharge + mode (proRate or molluTime)
- POST /expenses/:id/split      -> calculate final result
- GET  /groups/:groupId/summary -> total/my spending + history
