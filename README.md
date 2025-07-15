# Auth Service

A secure, production-ready authentication microservice built with FastAPI and PostgreSQL. This service provides JWT-based authentication, user registration, and user management capabilities for microservices architecture.

## 🚀 Features

- **JWT Authentication**: Secure token-based authentication
- **User Registration & Login**: Complete user lifecycle management
- **Password Security**: Bcrypt password hashing
- **Database Integration**: PostgreSQL with connection pooling
- **Health Monitoring**: Health check endpoints for Kubernetes
- **Input Validation**: Pydantic models for request/response validation
- **Error Handling**: Comprehensive error responses
- **Testing Suite**: 90%+ test coverage with pytest
- **Docker Ready**: Production-ready containerization

## 🛠 Tech Stack

- **Backend**: FastAPI (Python 3.11+)
- **Database**: PostgreSQL
- **Authentication**: JWT + bcrypt
- **Testing**: pytest, httpx, coverage
- **Code Quality**: black, flake8, isort, mypy
- **Security**: bandit, safety
- **Containerization**: Docker
- **Orchestration**: Kubernetes (via Skaffold)

## 📋 Prerequisites

- Python 3.11+
- PostgreSQL 12+
- Docker (optional)
- Kubernetes cluster (for deployment)

## 🚦 Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/eliazulai29/company1-auth-service.git
cd company1-auth-service
```

### 2. Install Dependencies
```bash
# Using pip
pip install -r requirements.txt

# Using uv (recommended)
uv sync
```

### 3. Environment Setup
Create a `.env` file in the root directory:
```env
# Database Configuration
DB_HOST=localhost
DB_NAME=auth_db
DB_USER=postgres
DB_PASSWORD=your_password
DB_PORT=5432

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-here
JWT_ALGORITHM=HS256
JWT_EXPIRE_HOURS=24

# Application Configuration
APP_HOST=0.0.0.0
APP_PORT=8000
```

### 4. Database Setup
```bash
# Create database
createdb auth_db

# Initialize tables (automatic on first run)
python main.py
```

### 5. Run Application
```bash
# Development
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Production
python main.py
```

## 📚 API Documentation

### Base URL
- **Development**: `http://localhost:8000`
- **Production**: `https://your-domain.com/auth`

### Endpoints

#### Health & Status
- `GET /` - Welcome message
- `GET /health` - Health check endpoint

#### Authentication
- `POST /register` - Register new user
- `POST /login` - User login
- `POST /logout` - User logout (requires auth)

#### User Management
- `GET /profile` - Get current user profile (requires auth)
- `GET /users` - List all users (requires auth)

### Request/Response Examples

#### Register User
```bash
curl -X POST "http://localhost:8000/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "securepassword123"
  }'
```

#### Login
```bash
curl -X POST "http://localhost:8000/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "securepassword123"
  }'
```

#### Access Protected Endpoint
```bash
curl -X GET "http://localhost:8000/profile" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 🧪 Testing

### Run Test Suite
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_auth_endpoints.py -v

# Run tests with live database (requires PostgreSQL)
pytest tests/test_database.py -v
```

### Test Coverage
The project maintains 90%+ test coverage across:
- Authentication endpoints
- Security functions
- Database operations
- Error handling
- Input validation

### Test Structure
```
tests/
├── conftest.py           # Test configuration and fixtures
├── test_auth_endpoints.py # API endpoint tests
├── test_security.py      # Security function tests
└── test_database.py      # Database integration tests
```

## 🐳 Docker Deployment

### Build Image
```bash
docker build -t auth-service:latest .
```

### Run Container
```bash
docker run -d \
  --name auth-service \
  -p 8000:8000 \
  -e DB_HOST=your-db-host \
  -e DB_PASSWORD=your-db-password \
  -e JWT_SECRET=your-jwt-secret \
  auth-service:latest
```

## ☸️ Kubernetes Deployment

### Using Skaffold
```bash
# Deploy to development
skaffold dev

# Deploy to production
skaffold run
```

### Manual Deployment
```bash
kubectl apply -f k8s/
```

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | `postgres-postgresql` | Database host |
| `DB_NAME` | `postgres` | Database name |
| `DB_USER` | `postgres` | Database user |
| `DB_PASSWORD` | `mysecurepass` | Database password |
| `DB_PORT` | `5432` | Database port |
| `JWT_SECRET` | `your-secret-key-here` | JWT signing secret |
| `JWT_ALGORITHM` | `HS256` | JWT algorithm |
| `JWT_EXPIRE_HOURS` | `24` | Token expiration time |
| `APP_HOST` | `0.0.0.0` | Application host |
| `APP_PORT` | `8000` | Application port |

## 🔒 Security Features

- **Password Hashing**: bcrypt with salt rounds
- **JWT Tokens**: Secure token generation and validation
- **Input Validation**: Pydantic models prevent injection attacks
- **CORS Protection**: Configurable cross-origin resource sharing
- **Rate Limiting**: Protection against brute force attacks
- **Secure Headers**: Security-focused HTTP headers

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Workflow
1. Install development dependencies
2. Run tests before committing
3. Follow code formatting standards (black, isort)
4. Ensure type hints (mypy)
5. Update documentation as needed

## 📊 Monitoring & Observability

- Health check endpoint: `/health`
- Structured logging with correlation IDs
- Metrics ready for Prometheus integration
- Database connection monitoring

## 🔗 Related Repositories

This auth service is part of a microservices architecture:
- [Infrastructure](https://github.com/eliazulai29/company1-infrastructure) - Kubernetes manifests and setup
- [Payment Service](https://github.com/eliazulai29/company1-payment-service) - Payment processing
- [Deployments](https://github.com/eliazulai29/company1-deployments) - CI/CD and operational docs

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- Create an issue for bug reports or feature requests
- Check existing issues before creating new ones
- Include relevant logs and environment details

---

**Built with ❤️ for secure, scalable authentication** 