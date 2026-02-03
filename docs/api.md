# API Spec (v1)

## Auth
- POST /auth/signup
- POST /auth/login         -> returns accessToken + refreshToken
- POST /auth/refresh       -> returns new accessToken
- POST /auth/logout
- GET  /auth/me

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
