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

## 🚀 Production Deployment

### **Live Production Environment**
- **Production URL**: `https://sppmaster.frappe.cloud`
- **Status**: ✅ DEPLOYED AND OPERATIONAL
- **Testing**: ✅ All endpoints verified and working

### **Production Test Results**

| **Test** | **Endpoint** | **Status** | **Result** |
|----------|-------------|------------|------------|
| Health Check | `/api/method/jwt_auth.api.auth.health` | ✅ PASS | Service running |
| User Login | `/api/method/jwt_auth.api.auth.login` | ✅ PASS | JWT generated |
| Public Key | `/api/method/jwt_auth.api.auth.public_key` | ✅ PASS | Key retrieved |
| JWKS | `/api/method/jwt_auth.api.auth.jwks` | ✅ PASS | JWKS format |

## 🔧 Installation

### Prerequisites
- Frappe/ERPNext instance
- Python 3.10+
- PyJWT library with crypto support
- cryptography library

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

### Production Endpoints

#### **Authentication Endpoint**
**POST** `https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.login`

**Request:**
```json
{
  "username": "user@domain.com",
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
    "email": "user@domain.com",
    "name": "User Full Name",
    "roles": ["System Manager", "Line Inspector", "Packer", ...]
  }
}
```

#### **JWKS Endpoint (Recommended for Clients)**
**GET** `https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.jwks`

**Response:**
```json
{
  "keys": [{
    "kty": "RSA",
    "use": "sig",
    "alg": "RS256", 
    "kid": "jwt-auth-key-1",
    "n": "base64url-encoded-modulus",
    "e": "AQAB"
  }]
}
```

#### **Public Key Endpoint**
**GET** `https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.public_key`

**Response:**
```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----\n...",
  "algorithm": "RS256",
  "use": "sig",
  "key_type": "RSA"
}
```

#### **Health Check**
**GET** `https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.health`

**Response:**
```json
{
  "status": "healthy",
  "message": "JWT Authentication service is running",
  "timestamp": "2025-07-10T10:15:00Z"
}
```

### Production JWT Payload Structure

The production JWT token contains the following claims as per client specifications:

```json
{
  "iss": "https://sppmaster.frappe.cloud",        // Production issuer
  "sub": "user@domain.com",                       // Subject (user email)
  "aud": "https://alphaworkz.api.com",           // Audience (client API)
  "exp": 1752231128,                             // Expiration timestamp
  "nbf": 1752144728,                             // Not Before timestamp
  "iat": 1752144728,                             // Issued At timestamp
  "jti": "b17019be-9a76-4651-a1cc-5dfb99375d96", // JWT ID (UUID)
  "userId": "username",                          // Custom: User ID
  "roles": [                                     // Custom: Manufacturing roles
    "System Manager",
    "Line Inspector", 
    "Packer",
    "Batch Operator",
    "Compound Inspector",
    "Quality Executive",
    "Production Executive",
    "Despatcher",
    "Incoming Inspector",
    "Mill Operator",
    "Blanker",
    "Lot Inspector",
    "U2 Supervisor",
    "U1 Supervisor", 
    "U3 Supervisor"
  ],
  "email": "user@domain.com",                    // Custom: User email
  "name": "User Full Name"                       // Custom: User name
}
```

## 🔐 Security & Key Management

### **Production Key Distribution**

**For Client Integration - Use These Endpoints:**

1. **JWKS (Automated Key Discovery) - Recommended:**
   ```
   https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.jwks
   ```

2. **Direct Public Key:**
   ```
   https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.public_key
   ```

### **Security Features**
- ✅ **RS256 Algorithm** - RSA with SHA-256 signing
- ✅ **Public Key Distribution** - Safe to share publicly
- ✅ **Private Key Security** - Kept secure on server only
- ✅ **HTTPS Endpoints** - All communication encrypted
- ✅ **Token Expiry** - 24-hour automatic expiration
- ✅ **Unique JWT IDs** - Prevents replay attacks

### Manufacturing Roles Supported

The JWT includes all manufacturing roles from ERPNext:
- **System Management**: System Manager
- **Supervisory Roles**: U1 Supervisor, U2 Supervisor, U3 Supervisor
- **Quality Control**: Quality Executive, Line Inspector, Lot Inspector, Incoming Inspector, Compound Inspector
- **Production**: Production Executive, Mill Operator, Batch Operator, Blanker
- **Logistics**: Packer, Despatcher

## 🧪 Testing

### Production Testing

```bash
# Health check
curl -X GET "https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.health"

# Login test
curl -X POST "https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.login" \
  -H "Content-Type: application/json" \
  -d '{"username": "your-email@domain.com", "password": "your-password"}'

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

## 🔄 Client Integration

### **Automated Key Discovery (Recommended)**

```javascript
// Node.js example with automatic JWKS key discovery
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
    console.log('Valid token:', decoded);
    console.log('User roles:', decoded.roles);
    console.log('User ID:', decoded.userId);
  }
});
```

### **Manual Public Key Verification**

```javascript
// Manual verification with public key
const jwt = require('jsonwebtoken');

const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2UrAN+/9AojOO1+/jK3s
wJAsFnkM52ukfWARp9TJJostomLo3qiokXgr4NuB89E5FuecVd1YaP2ni1MsX5ao
q8ZPsHjkzS8xntUhSpvt22E8abn8LTBHXuHh2Y79Uz+1hI2g7rWE2C1vj0BOWcw8
jE6lSl/Btp4y8+eZGpyYuwRgz9DFBYqxcM+7y9CBZrknQ/SQzb845niARm18FUSp
GhmuN3GOQ7Pcj7WOYaXt6m5AVu3XUzAY/xnnBr/aLr/JulQ5bohE3LIHmbvPlxNP
H2k8faYjB8E7XWHsRXihncHlXBXxCqwUa34eoElYhnNt8pKVOJLujWHJBu5BTH95
BwIDAQAB
-----END PUBLIC KEY-----`;

try {
  const payload = jwt.verify(token, publicKey, {
    algorithms: ['RS256'],
    audience: 'https://alphaworkz.api.com',
    issuer: 'https://sppmaster.frappe.cloud'
  });
  
  console.log('User:', payload.userId);
  console.log('Roles:', payload.roles);
  console.log('Email:', payload.email);
} catch (error) {
  console.error('Invalid token:', error.message);
}
```

### **API Requests with JWT**

```javascript
// Using JWT for subsequent API requests
const headers = {
  'Authorization': `Bearer ${jwt_token}`,
  'Content-Type': 'application/json'
};

// Example API call
fetch('https://your-client-api.com/manufacturing/data', { 
  headers,
  method: 'GET'
})
.then(response => response.json())
.then(data => {
  console.log('Manufacturing data:', data);
});

// Example with role-based access
fetch('https://your-client-api.com/quality/inspection', {
  headers,
  method: 'POST',
  body: JSON.stringify({
    inspector_role: 'Quality Executive',
    batch_id: 'BATCH001'
  })
})
.then(response => response.json())
.then(result => {
  console.log('Inspection result:', result);
});
```

## 🛠️ Configuration

### JWT Settings

Configure JWT behavior in `site_config.json`:

```json
{
  "jwt_expiry_hours": 24,
  "jwt_issuer": "https://sppmaster.frappe.cloud",
  "jwt_audience": "https://alphaworkz.api.com"
}
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
│   │   ├── jwt_private_key.pem  # RSA private key (server only)
│   │   └── jwt_public_key.pem   # RSA public key (shareable)
│   └── hooks.py                 # Frappe hooks
├── pyproject.toml               # Dependencies (PyJWT, cryptography)
├── .gitignore                   # Git ignore patterns
└── README.md                    # This documentation
```

## 🚀 Deployment

### **Production Deployment (Completed)**

✅ **Deployed to**: `https://sppmaster.frappe.cloud`  
✅ **Status**: OPERATIONAL  
✅ **Testing**: All endpoints verified  
✅ **Security**: RS256 keys generated and secured  

### **Deploy to Your Instance**

1. **Add to Frappe Cloud:**
   - Add this GitHub repository to your Frappe Cloud bench
   - Deploy to your production site
   - Ensure dependencies are installed

2. **Update Configuration:**
   - Set your production issuer URL
   - Configure proper expiry times
   - Secure RSA key storage

3. **Test Deployment:**
   - Verify all endpoints work
   - Test JWT generation and verification
   - Confirm role mappings

## 📞 **Client Handoff Information**

### **Ready for Client Integration**

**Share with your client:**

1. **GitHub Repository**: https://github.com/iyyanarr/frappe-jwt-auth
2. **Production Login**: `https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.login`
3. **JWKS Endpoint**: `https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.jwks`
4. **Public Key**: `https://sppmaster.frappe.cloud/api/method/jwt_auth.api.auth.public_key`

**What Your Client Gets:**
- ✅ Pure JWT Authentication (exactly as requested)
- ✅ RS256 Encryption (industry standard)
- ✅ All Manufacturing Roles (complete ERPNext integration)
- ✅ 24-hour Token Validity (configurable)
- ✅ Production-Ready Endpoints (scalable and secure)
- ✅ Standard Key Distribution (JWKS compliance)

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
**Production Status: ✅ DEPLOYED AND OPERATIONAL** 🚀