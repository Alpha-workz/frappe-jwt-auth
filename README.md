# Frappe JWT Authentication App

A custom Frappe application that provides JWT authentication with RS256 encryption for client applications. This app allows external clients to authenticate users against Frappe/ERPNext and receive pure JWT tokens with manufacturing roles integration.

## 🎯 Features

- **RS256 JWT Authentication** - RSA encrypted JWT tokens
- **Pure JWT Response** - Stateless tokens for client applications
- **Manufacturing Roles Integration** - Includes all ERPNext manufacturing roles
- **Frappe User Validation** - Authenticates against existing Frappe users
- **24-hour Token Expiry** - Configurable token lifetime
- **Client-Specified Payload** - JWT structure matches client requirements

## 🔧 Installation

### Prerequisites
- Frappe/ERPNext instance
- Python 3.10+
- PyJWT library with crypto support

### Install the App

1. **Clone the repository:**
   ```bash
   cd frappe-bench/apps
   git clone https://github.com/iyyanarr/frappe-jwt-auth.git jwt_auth
   ```

2. **Install to your site:**
   ```bash
   cd frappe-bench
   bench --site your-site-name install-app jwt_auth
   ```

3. **Install dependencies:**
   ```bash
   bench pip install "PyJWT[crypto]>=2.8.0"
   ```

## 🚀 Usage

### Authentication Endpoint

**POST** `/api/method/jwt_auth.api.auth.login`

**Request:**
```json
{
  "username": "your-username",
  "password": "your-password"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "expires_at": "2025-07-11T10:08:34.878796",
  "user": {
    "userId": "username",
    "email": "user@example.com",
    "name": "User Name",
    "roles": ["Manufacturing Role 1", "Manufacturing Role 2"]
  }
}
```

### JWT Payload Structure

The JWT token contains the following claims as per client specifications:

```json
{
  "iss": "https://your-site.frappe.cloud",    // Issuer
  "sub": "username",                          // Subject (username)
  "aud": "https://alphaworkz.api.com",       // Audience (client API)
  "exp": 1752228514,                         // Expiration timestamp
  "nbf": 1752142114,                         // Not Before timestamp
  "iat": 1752142114,                         // Issued At timestamp
  "jti": "unique-uuid",                      // JWT ID
  "userId": "username",                      // Custom: User ID
  "roles": ["role1", "role2"],              // Custom: User roles
  "email": "user@example.com",              // Custom: User email
  "name": "User Name"                       // Custom: User name
}
```

## 🔐 Security

### RSA Key Pair

The app generates RSA keys for JWT signing:
- **Private Key:** Used for JWT signing (kept secure on server)
- **Public Key:** Shared with clients for JWT verification

**Get the public key for client verification:**
```bash
cat apps/jwt_auth/jwt_auth/config/jwt_public_key.pem
```

### Manufacturing Roles Supported

The JWT includes all manufacturing roles from ERPNext:
- Compound Inspector
- U1/U2/U3 Supervisor  
- Packer, Despatcher
- Mill Operator, Batch Operator
- Quality Executive, Production Executive
- Line Inspector, Lot Inspector, Incoming Inspector
- And more...

## 🛠️ Configuration

### JWT Settings

Configure JWT behavior in `site_config.json`:

```json
{
  "jwt_expiry_hours": 24,
  "jwt_issuer": "https://your-site.frappe.cloud",
  "jwt_audience": "https://client-api.com"
}
```

### Health Check

Test the app installation:

**GET** `/api/method/jwt_auth.api.auth.health`

**Response:**
```json
{
  "status": "healthy",
  "message": "JWT Authentication service is running",
  "timestamp": "2025-07-10T10:15:00Z"
}
```

## 🧪 Testing

### Local Testing

```bash
# Health check
curl -X GET "http://localhost:8000/api/method/jwt_auth.api.auth.health"

# Login test
curl -X POST "http://localhost:8000/api/method/jwt_auth.api.auth.login" \
  -H "Content-Type: application/json" \
  -d '{"username": "Administrator", "password": "admin"}'
```

### JWT Verification

```python
import jwt

# Decode JWT (client-side verification)
public_key = """-----BEGIN PUBLIC KEY-----
...your public key...
-----END PUBLIC KEY-----"""

payload = jwt.decode(token, public_key, algorithms=["RS256"])
print(payload)
```

## 📁 Project Structure

```
jwt_auth/
├── jwt_auth/
│   ├── api/
│   │   ├── __init__.py
│   │   └── auth.py              # Authentication endpoints
│   ├── utils/
│   │   ├── __init__.py
│   │   └── jwt_utils.py         # JWT utility functions
│   ├── config/
│   │   ├── jwt_private_key.pem  # RSA private key
│   │   └── jwt_public_key.pem   # RSA public key
│   └── hooks.py                 # Frappe hooks
├── pyproject.toml               # Dependencies
└── README.md                    # This file
```

## 🔄 Client Integration

### JWT Verification (Client Side)

```javascript
// Node.js example
const jwt = require('jsonwebtoken');
const fs = require('fs');

const publicKey = fs.readFileSync('jwt_public_key.pem');
const token = 'eyJhbGciOiJSUzI1NiIs...';

try {
  const payload = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
  console.log('User:', payload.userId);
  console.log('Roles:', payload.roles);
} catch (error) {
  console.error('Invalid token:', error.message);
}
```

### API Request with JWT

```javascript
// Using the JWT token for API requests
const headers = {
  'Authorization': `Bearer ${jwt_token}`,
  'Content-Type': 'application/json'
};

fetch('https://your-api-endpoint.com/data', { headers })
  .then(response => response.json())
  .then(data => console.log(data));
```

## 🚀 Deployment

### Production Deployment

1. **Deploy to Frappe Cloud:**
   - Push this repository to your Git provider
   - Add the app to your Frappe Cloud bench
   - Install to your production site

2. **Update Configuration:**
   - Set production JWT issuer URL
   - Configure proper expiry times
   - Secure RSA key storage

3. **Share Public Key:**
   - Provide the public key to client applications
   - Document the JWT payload structure
   - Set up monitoring and logging

## 📝 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📞 Support

For issues and questions:
- Create an issue in this repository
- Contact: iyyanarr@alphaworkz.com

---

**Built for Frappe/ERPNext integration with manufacturing workflows** 🏭