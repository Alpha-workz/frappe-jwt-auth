# Frappe JWT Authentication App

A custom Frappe application that provides JWT authentication with RS256 encryption for client applications. This app allows external clients to authenticate users against Frappe/ERPNext and receive pure JWT tokens with manufacturing roles integration.

## 🎯 Features

- **RS256 JWT Authentication** - RSA encrypted JWT tokens
- **Pure JWT Response** - Stateless tokens for client applications
- **Manufacturing Roles Integration** - Includes all ERPNext manufacturing roles
- **Frappe User Validation** - Authenticates against existing Frappe users
- **24-hour Token Expiry** - Configurable token lifetime
- **Client-Specified Payload** - JWT structure matches client requirements
- **JWKS Support** - Industry standard key distribution
- **Production Ready** - Deployed and tested on Frappe Cloud

## 🌐 Production Deployment

**Live Production Environment:** `https://sppmaster.frappe.cloud`

### ✅ Production Test Results

| **Endpoint** | **Status** | **Description** |
|-------------|------------|-----------------|
| `/api/method/jwt_auth.api.auth.health` | ✅ LIVE | Service health check |
| `/api/method/jwt_auth.api.auth.login` | ✅ LIVE | User authentication & JWT generation |
| `/api/method/jwt_auth.api.auth.public_key` | ✅ LIVE | Public key for JWT verification |
| `/api/method/jwt_auth.api.auth.jwks` | ✅ LIVE | JSON Web Key Set (JWKS) endpoint |

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
   bench pip install cryptography
   ```

## 🚀 Usage

### Production Authentication Endpoint

**POST** `https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.login`

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
  "expires_at": "2025-07-11T10:52:08.750530",
  "user": {
    "userId": "username",
    "email": "user@example.com",
    "name": "User Name",
    "roles": ["Manufacturing Role 1", "Manufacturing Role 2"]
  }
}
```

### Production JWT Payload Structure

The production JWT token contains the following verified structure:

```json
{
  "iss": "https://sppmaster.frappe.cloud",     // Production issuer
  "sub": "user@example.com",                   // Subject (user email)
  "aud": "https://alphaworkz.api.com",        // Audience (client API)
  "exp": 1752231128,                          // Expiration timestamp
  "nbf": 1752144728,                          // Not Before timestamp
  "iat": 1752144728,                          // Issued At timestamp
  "jti": "b17019be-9a76-4651-a1cc-5dfb99375d96", // Unique JWT ID
  "userId": "username",                        // Custom: User ID
  "roles": ["role1", "role2"],                // Custom: User roles
  "email": "user@example.com",                // Custom: User email
  "name": "User Name"                         // Custom: User name
}
```

## 🔐 Security & Key Management

### Production Key Endpoints

**JWKS Endpoint (Recommended for Automated Key Discovery):**
```bash
GET https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.jwks
```

**Direct Public Key Endpoint:**
```bash
GET https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.public_key
```

### Manufacturing Roles Supported

The JWT includes all manufacturing roles from ERPNext:
- **Supervisory Roles**: U1 Supervisor, U2 Supervisor, U3 Supervisor
- **Quality Roles**: Quality Executive, Line Inspector, Lot Inspector, Incoming Inspector, Compound Inspector
- **Production Roles**: Production Executive, Mill Operator, Batch Operator, Blanker, Packer
- **Operations**: Despatcher
- **Administrative**: System Manager

### Key Distribution Best Practices

✅ **Public keys are safe to share** - designed for verification  
✅ **JWKS endpoints follow industry standards** (Google, Microsoft, Auth0)  
✅ **Keys served over HTTPS** - prevents tampering  
✅ **Key versioning supported** - enables smooth key rotation  

## 🧪 Testing

### Production Testing

```bash
# Health check
curl -X GET "https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.health"

# Login test
curl -X POST "https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.login" \
  -H "Content-Type: application/json" \
  -d '{"username": "your-username", "password": "your-password"}'

# Get public key
curl -X GET "https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.public_key"

# Get JWKS
curl -X GET "https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.jwks"
```

### Local Testing

```bash
# Health check
curl -X GET "http://localhost:8000/api/method/jwt_auth.api.auth.health"

# Login test
curl -X POST "http://localhost:8000/api/method/jwt_auth.api.auth.login" \
  -H "Content-Type: application/json" \
  -d '{"username": "Administrator", "password": "admin"}'
```

### JWT Verification (Client Side)

```python
import jwt

# Using production public key endpoint
import requests

# Get public key
response = requests.get('https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.public_key')
public_key = response.json()['message']['public_key']

# Verify JWT
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

### Automated Key Discovery (Recommended)

```javascript
// Node.js example with JWKS
const jwksClient = require('jwks-rsa');
const jwt = require('jsonwebtoken');

const client = jwksClient({
  jwksUri: 'https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.jwks'
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

// Verify JWT
jwt.verify(token, getKey, {
  algorithms: ['RS256'],
  audience: 'https://alphaworkz.api.com',
  issuer: 'https://sppmaster.frappe.cloud'
}, (err, decoded) => {
  if (err) {
    console.error('Invalid token:', err);
  } else {
    console.log('User:', decoded.userId);
    console.log('Roles:', decoded.roles);
  }
});
```

### Direct Public Key Method

```javascript
// Using direct public key endpoint
const axios = require('axios');

async function verifyToken(token) {
  // Get public key
  const keyResponse = await axios.get(
    'https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.public_key'
  );
  
  const publicKey = keyResponse.data.message.public_key;
  
  // Verify JWT
  try {
    const payload = jwt.verify(token, publicKey, {
      algorithms: ['RS256'],
      audience: 'https://alphaworkz.api.com',
      issuer: 'https://sppmaster.frappe.cloud'
    });
    
    return { valid: true, payload };
  } catch (error) {
    return { valid: false, error: error.message };
  }
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

## 🌟 Production Features

### ✅ Verified Production Capabilities

- **RS256 Encryption**: Industry-standard asymmetric signing
- **24-Hour Token Validity**: Configurable expiry times
- **Role-Based Access**: Complete ERPNext manufacturing roles
- **JWKS Compliance**: Standard key distribution format
- **Health Monitoring**: Service health check endpoint
- **Secure Key Management**: Public key distribution over HTTPS

### 🏭 Manufacturing Integration

Perfect integration with ERPNext manufacturing workflows:
- **Quality Control**: Inspector roles for quality gates
- **Production Management**: Supervisor and operator roles
- **Inventory Operations**: Packer and despatcher roles
- **System Administration**: Full system management capabilities

## 🚀 Deployment

### Production Deployment (Frappe Cloud)

✅ **Already deployed and tested on:**
- **URL**: `https://sppmaster.frappe.cloud`
- **Status**: Production ready
- **Authentication**: Working with real user credentials
- **Key Distribution**: JWKS and direct endpoints active

### Custom Deployment

1. **Deploy to your Frappe Cloud instance:**
   - Add this repository to your Frappe Cloud bench
   - Install the app to your site
   - Configure production URLs

2. **Update Configuration:**
   ```json
   {
     "jwt_issuer": "https://your-site.frappe.cloud",
     "jwt_audience": "https://your-client-api.com",
     "jwt_expiry_hours": 24
   }
   ```

## 📊 Client Requirements Compliance

### ✅ All Client Requirements Met

| **Requirement** | **Implementation** | **Status** |
|----------------|-------------------|------------|
| RS256 Algorithm | ✅ RSA with SHA-256 | COMPLETE |
| Pure JWT Response | ✅ Stateless tokens | COMPLETE |
| Client Payload Format | ✅ Exact specification | COMPLETE |
| Public Key Distribution | ✅ JWKS + Direct endpoints | COMPLETE |
| Manufacturing Roles | ✅ All ERPNext roles included | COMPLETE |
| Production Ready | ✅ Deployed and tested | COMPLETE |

### 📝 JWT Payload Compliance

Client's exact specification implemented:
```json
{
  "iss": "https://sppmaster.frappe.cloud",     ✅ Issuer
  "sub": "username",                           ✅ Subject  
  "aud": "https://alphaworkz.api.com",        ✅ Audience
  "exp": 1752231128,                          ✅ Expiration
  "nbf": 1752144728,                          ✅ Not Before
  "iat": 1752144728,                          ✅ Issued At
  "jti": "unique-uuid",                       ✅ JWT ID
  "userId": "username",                       ✅ User ID
  "roles": ["manufacturing roles"],          ✅ User Roles
  "email": "user@example.com",               ✅ Email
  "name": "User Name"                        ✅ Full Name
}
```

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
- **Repository**: Create an issue in this GitHub repository
- **Email**: iyyanarr@alphaworkz.com
- **Production Support**: Tested and verified on `https://sppmaster.frappe.cloud`

---

**Built for Frappe/ERPNext integration with manufacturing workflows** 🏭  
**Production Ready | RS256 Encrypted | JWKS Compliant | Manufacturing Integrated** ✅