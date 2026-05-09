# SecureVault

A secure note management web application built to demonstrate the Software Development Lifecycle (SDLC) with cybersecurity principles integrated at every phase.

---

## What It Does

SecureVault allows users to register, log in, and manage personal notes securely. Every design and code decision prioritises security over convenience, making it a practical reference for secure application development.

---

## Security Features

| Feature | Implementation |
|---|---|
| Password Hashing | bcrypt with cost factor 12 |
| Authentication | JWT (HS256), 2-hour expiry |
| Brute Force Protection | express-rate-limit (10 attempts per 15 min) |
| Input Validation | express-validator on all inputs |
| XSS Prevention | Helmet CSP headers + HTML escaping in frontend |
| IDOR Protection | Ownership enforced server-side on every note operation |
| Role-Based Access | admin / user roles with middleware enforcement |
| Security Headers | Helmet.js (14 headers including HSTS, X-Frame-Options) |
| Audit Logging | Every security event logged with timestamp, IP, and user ID |
| Error Safety | Stack traces never exposed to client |

---

## Tech Stack

- **Backend**: Node.js + Express.js
- **Database**: lowdb (JSON file-based, no native modules required)
- **Auth**: bcryptjs + jsonwebtoken
- **Security**: helmet, express-rate-limit, express-validator, cors
- **Frontend**: Vanilla HTML/CSS/JavaScript

---

## Getting Started

### Prerequisites
- Node.js v16 or higher
- npm

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/securevault.git
cd securevault

# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit .env and set a strong JWT_SECRET

# Start the server
npm start
```

Open your browser at `http://localhost:3000`

---

## Project Structure

```
securevault/
├── server.js                 # Main Express application
├── package.json
├── .env.example              # Environment variable template
├── public/
│   └── index.html            # Frontend SPA
├── src/
│   ├── middleware/
│   │   ├── auth.js           # JWT verify + RBAC
│   │   ├── rateLimiter.js    # Brute force protection
│   │   └── validator.js      # Input validation rules
│   ├── routes/
│   │   ├── auth.js           # Register + Login
│   │   ├── notes.js          # CRUD notes (protected)
│   │   └── admin.js          # Admin panel (admin role only)
│   └── utils/
│       ├── db.js             # Database initialisation
│       └── logger.js         # Audit log utility
├── tests/
│   └── security.test.js      # Security test suite
└── data/
    └── securevault.json      # Auto-created database file
```

---

## Running Tests

Make sure the server is running, then in a second terminal:

```bash
node tests/security.test.js
```

Expected output: 10 tests, all passing.

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | /api/auth/register | None | Create account |
| POST | /api/auth/login | None | Login, get JWT |
| GET | /api/notes | Bearer token | List own notes |
| POST | /api/notes | Bearer token | Create note |
| PUT | /api/notes/:id | Bearer token | Update own note |
| DELETE | /api/notes/:id | Bearer token | Delete own note |
| GET | /api/admin/users | Admin token | List all users |
| GET | /api/admin/audit-logs | Admin token | View audit trail |

---

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| PORT | Server port | 3000 |
| JWT_SECRET | Secret key for JWT signing | (must be set) |
| ALLOWED_ORIGIN | Trusted CORS origin | http://localhost:3000 |
| NODE_ENV | development or production | development |

---

## OWASP Top 10 Mitigations

| Risk | Mitigation in SecureVault |
|---|---|
| A01 Broken Access Control | RBAC middleware + per-resource ownership checks |
| A02 Cryptographic Failures | bcrypt hashing, JWT signing, HTTPS-ready HSTS headers |
| A03 Injection | express-validator sanitises all inputs before processing |
| A04 Insecure Design | Threat model documented in project report |
| A05 Security Misconfiguration | Helmet.js, CORS whitelist, no stack trace exposure |
| A06 Vulnerable Components | Dependencies pinned; audit with npm audit |
| A07 Auth Failures | Rate limiting, constant-time comparison, short JWT expiry |
| A09 Logging Failures | Full audit log of every auth and data event |
