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
- **Enterprise CI/CD**: Automated quality gates and deployment pipeline

## 🏭 Enterprise CI/CD Pipeline

This service features a **production-grade CI/CD pipeline** with automated quality gates:

### 🔄 **GitHub Actions Workflow**
- **Automated Testing**: Full test suite with PostgreSQL integration
- **Code Quality**: Black, isort, flake8, mypy enforcement
- **Security Scanning**: Bandit (SAST), Safety (dependency scan), Trivy (container scan)
- **Docker Build**: Multi-stage production builds with security hardening
- **Container Registry**: Automated publishing to GitHub Container Registry
- **Coverage Reporting**: Automated PR comments with test coverage metrics

### 🛡️ **Quality Gates**
All code changes must pass:
1. **Code Quality & Security** (39s avg): Formatting, linting, type checking, security scans
2. **Test Suite** (1m avg): 45% overall coverage, 100% PR coverage requirement
3. **Docker Build & Security** (49s avg): Multi-stage build + Trivy vulnerability scan
4. **Pipeline Summary** (4s avg): Automated reporting and status aggregation

### 🏷️ **Container Tagging Strategy**
- `latest` - Latest main branch build
- `sha-{commit}` - Specific commit builds
- `{branch}` - Feature branch builds

### 📋 **Branch Protection**
- **Required Status Checks**: All CI jobs must pass
- **Pull Request Required**: No direct pushes to main
- **Linear History**: Enforced for clean git history
- **Self-Merge Enabled**: 0 required reviewers for solo development

## 🛠 Tech Stack

- **Backend**: FastAPI (Python 3.11+)
- **Database**: PostgreSQL
- **Authentication**: JWT + bcrypt
- **Testing**: pytest, httpx, coverage
- **Code Quality**: black, flake8, isort, mypy
- **Security**: bandit, safety, trivy
- **CI/CD**: GitHub Actions with quality gates
- **Registry**: GitHub Container Registry (ghcr.io)
- **Containerization**: Docker (multi-stage builds)
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

### 2. Development Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt

# Setup pre-commit hooks (optional but recommended)
pre-commit install
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

### Local Development
```bash
# Run all tests with coverage
pytest --cov=. --cov-report=html --cov-report=term

# Run specific test categories
pytest tests/test_auth_endpoints.py -v  # API tests
pytest tests/test_security.py -v        # Security tests
pytest tests/test_database.py -v        # Database tests

# Quality checks (same as CI)
black --check .                    # Code formatting
isort --check-only .               # Import sorting
flake8 .                          # Linting
mypy .                            # Type checking
bandit -r . -f json               # Security analysis
safety check                      # Dependency vulnerabilities
```

### CI Pipeline Testing
The automated CI pipeline runs on every pull request:

1. **Code Quality & Security**: `black`, `isort`, `flake8`, `mypy`, `bandit`, `safety`
2. **Test Suite**: Full pytest suite with PostgreSQL integration
3. **Docker Security**: Multi-stage build + Trivy vulnerability scanning
4. **Coverage**: Automatic PR comments with coverage metrics

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

## 🐳 Container Deployment

### Pre-built Images
```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/eliazulai29/company1-auth-service:latest

# Run pre-built container
docker run -d \
  --name auth-service \
  -p 8000:8000 \
  -e DB_HOST=your-db-host \
  -e DB_PASSWORD=your-db-password \
  -e JWT_SECRET=your-jwt-secret \
  ghcr.io/eliazulai29/company1-auth-service:latest
```

### Build Locally
```bash
# Build production image
docker build -t auth-service:latest .

# Build development image
docker build --target development -t auth-service:dev .
```

## 🔄 Development Workflow

### Feature Development
1. **Create Feature Branch**: `git checkout -b feature/your-feature`
2. **Develop & Test**: Write code, add tests, run local quality checks
3. **Create Pull Request**: Push branch and open PR
4. **Automated Review**: CI pipeline runs all quality gates
5. **Review Results**: Check PR comments for coverage and quality metrics
6. **Merge**: Self-merge after all checks pass ✅

### Quality Standards
- **Test Coverage**: Minimum 90% overall, 100% for new code
- **Code Quality**: All linting and formatting checks must pass
- **Security**: No CRITICAL/HIGH vulnerabilities allowed
- **Type Safety**: Full mypy type checking compliance

## 🔧 Configuration

### Container Registry
Images are automatically published to:
- **Registry**: `ghcr.io/eliazulai29/company1-auth-service`
- **Tags**: `latest`, `sha-{commit}`, `{branch}`
- **Security**: Trivy scanned for vulnerabilities

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

### Application Security
- **Password Hashing**: bcrypt with salt rounds
- **JWT Tokens**: Secure token generation and validation
- **Input Validation**: Pydantic models prevent injection attacks
- **CORS Protection**: Configurable cross-origin resource sharing
- **Rate Limiting**: Protection against brute force attacks
- **Secure Headers**: Security-focused HTTP headers

### CI/CD Security
- **SAST Scanning**: Bandit static analysis for security vulnerabilities
- **Dependency Scanning**: Safety checks for known CVEs in dependencies
- **Container Scanning**: Trivy scans for OS and application vulnerabilities
- **Automated Updates**: Security patches integrated into CI pipeline
- **Supply Chain Security**: Verified container base images

## 🤝 Contributing

### Prerequisites
- Python 3.11+
- PostgreSQL for integration tests
- Docker for container testing

### Development Workflow
1. **Fork & Clone**: Fork repository and clone locally
2. **Setup Environment**: Install dependencies and setup `.env`
3. **Create Branch**: `git checkout -b feature/amazing-feature`
4. **Develop**: Write code following existing patterns
5. **Test Locally**: Run full test suite and quality checks
6. **Commit Changes**: `git commit -m 'Add amazing feature'`
7. **Push Branch**: `git push origin feature/amazing-feature`
8. **Open Pull Request**: Create PR with description
9. **Review CI Results**: Ensure all quality gates pass
10. **Merge**: Self-merge after approval

### Code Standards
- **Formatting**: `black` (88 chars), `isort` for imports
- **Linting**: `flake8` with custom configuration
- **Type Hints**: Full `mypy` compliance required
- **Testing**: pytest with minimum 90% coverage
- **Security**: Pass all `bandit` and `safety` checks

## 📊 Monitoring & Observability

### Health Endpoints
- **Application Health**: `/health` - Service status
- **Database Health**: Automatic connection monitoring
- **Kubernetes Probes**: Readiness and liveness endpoints

### Metrics & Logging
- Structured logging with correlation IDs
- Metrics ready for Prometheus integration
- Database connection pool monitoring
- Request/response tracking

### CI/CD Metrics
- **Build Times**: ~2 minutes total pipeline
- **Test Coverage**: 45% overall, 100% PR coverage
- **Security Posture**: Automated vulnerability tracking
- **Quality Metrics**: Code quality trends over time

## 🔗 Related Repositories

This auth service is part of a comprehensive microservices architecture:

- **[Infrastructure](https://github.com/eliazulai29/company1-infrastructure)** - Kubernetes manifests and ArgoCD setup
- **[Payment Service](https://github.com/eliazulai29/company1-payment-service)** - Payment processing with enterprise CI/CD
- **[Deployments](https://github.com/eliazulai29/company1-deployments)** - GitOps configurations and operational docs
- **[Framework Root](https://github.com/eliazulai29/customer-k8s-framework)** - Overall architecture and roadmap

## 📈 Enterprise Features

### Production Ready
✅ **Multi-stage Docker builds** with security hardening  
✅ **Automated testing** with PostgreSQL integration  
✅ **Security scanning** at multiple levels  
✅ **Code quality enforcement** with automated gates  
✅ **Container registry** with automated publishing  
✅ **Branch protection** with required status checks  
✅ **GitOps ready** for ArgoCD integration  

### Professional Workflow
✅ **Self-merge capability** for solo development  
✅ **Automated coverage reporting** on pull requests  
✅ **Quality metrics** tracked over time  
✅ **Security posture** continuously monitored  
✅ **Dependency management** with automated updates  

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: Create an issue for bug reports or feature requests
- **Documentation**: Check this README and inline code comments
- **CI/CD Help**: Review GitHub Actions logs for pipeline issues
- **Security**: Report security issues via private channels

---

**🏭 Enterprise-grade microservice with automated quality assurance and deployment pipeline**
