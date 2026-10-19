# BridgeMate REST API

Base path: `/api`

Except for health, plans, registration and login, send the JWT returned at login:

```http
Authorization: Bearer <token>
Content-Type: application/json
```

Roles are `senior`, `helper`, `family` and `admin`. A helper account can also be linked to a relative through the family-link flow. Public registration cannot create administrators.

## Public and authentication

| Method | Route | Purpose |
|---|---|---|
| GET | `/health` | Service status |
| GET | `/plans` | Current JPY plan catalogue |
| POST | `/auth/register` | Register senior, helper or family user |
| POST | `/auth/login` | Sign in using phone and password |

## Accounts and helpers

| Method | Route | Access |
|---|---|---|
| GET | `/me` | Signed-in user |
| PATCH | `/me` | Signed-in user |
| PATCH | `/helpers/me` | Helper profile and availability |
| POST | `/helpers/verification` | Helper submits document references |
| GET | `/helpers` | Signed-in users; verified/available helpers only |
| GET | `/admin/verifications` | Admin |
| PATCH | `/admin/verifications/:id` | Admin approves or rejects |

## Family and assistance

| Method | Route | Purpose |
|---|---|---|
| POST | `/family-links/invite` | Invite a senior by phone |
| PATCH | `/family-links/:id/respond` | Senior approves permissions |
| GET | `/family-links` | List the user's links |
| POST | `/requests` | Create a help request |
| GET | `/requests` | List accessible requests |
| GET | `/requests/:id` | Request, event and consent history |
| POST | `/requests/:id/accept` | Verified available helper accepts |
| PATCH | `/requests/:id/status` | Assigned helper advances status |
| POST | `/requests/:id/cancel` | Participant cancels with reason |
| POST | `/requests/:id/escalate` | Record and notify escalation |
| POST | `/requests/:id/review` | Review a completed request |

## Consent and location

| Method | Route | Purpose |
|---|---|---|
| PUT | `/requests/:id/consent/:type` | Senior grants/revokes `location`, `screen_share` or `family_updates` |
| PUT | `/requests/:id/location` | Senior/helper updates current coordinates |
| GET | `/requests/:id/locations` | Authorised participant/family reads coordinates |

Screen-share consent is only an auditable permission record. Media capture and transport are deliberately not implemented.

## Billing records and notifications

| Method | Route | Purpose |
|---|---|---|
| POST | `/subscriptions` | Start a plan using payment-provider reference |
| GET | `/subscriptions` | List accessible plan records |
| POST | `/subscriptions/:id/cancel` | Cancel monthly/yearly plan |
| GET | `/notifications` | List latest notifications |
| PATCH | `/notifications/:id/read` | Mark one notification read |

## Examples

### Register

```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "role":"senior",
    "fullName":"Taro Tanaka",
    "phone":"09012345678",
    "password":"a-unique-password-with-12-chars",
    "locale":"ja"
  }'
```

### Create a request

```bash
curl -X POST http://localhost:3000/api/requests \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "category":"ehailing",
    "mode":"virtual",
    "description":"Please guide me through booking a taxi",
    "priceYen":1500
  }'
```

### Grant location consent

```bash
curl -X PUT http://localhost:3000/api/requests/1/consent/location \
  -H "Authorization: Bearer $SENIOR_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"granted":true}'
```

### Advance an assigned job

```bash
curl -X PATCH http://localhost:3000/api/requests/1/status \
  -H "Authorization: Bearer $HELPER_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"status":"helping","note":"Virtual guidance started"}'
```

Validation failures return HTTP 400; authentication failures 401; permission failures 403; missing records 404; and invalid state conflicts 409. Unexpected errors return a generic HTTP 500 response.
