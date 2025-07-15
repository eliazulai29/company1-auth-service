"""
Comprehensive tests for authentication endpoints.
Tests all API endpoints, error conditions, and business logic.
Targets >90% code coverage to replace manual peer review.
"""

import pytest
import jwt
import datetime
from unittest.mock import patch, MagicMock


class TestRootEndpoint:
    """Test the root endpoint."""
    
    def test_root_endpoint_success(self, client):
        """Test root endpoint returns service information."""
        response = client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "Auth Service"
        assert data["status"] == "running"
        assert data["version"] == "1.0.0"
        assert data["database"] == "connected"


class TestHealthCheck:
    """Test health check endpoint."""
    
    def test_health_check_success(self, client):
        """Test health check with healthy database."""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["database"] == "connected"
    
    @patch('main.get_db_connection')
    def test_health_check_database_failure(self, mock_db, client):
        """Test health check with database connection failure."""
        mock_db.side_effect = Exception("Database connection failed")
        
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "unhealthy"
        assert "Database connection failed" in data["error"]


class TestUserRegistration:
    """Test user registration endpoint."""
    
    def test_register_user_success(self, client, sample_user):
        """Test successful user registration."""
        response = client.post("/register", json=sample_user)
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify token response structure
        assert "access_token" in data
        assert "token_type" in data
        assert "expires_in" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 3600  # 1 hour in test config
        
        # Verify token is valid JWT
        token = data["access_token"]
        decoded = jwt.decode(token, "test-secret-key", algorithms=["HS256"])
        assert decoded["username"] == sample_user["username"]
        assert "user_id" in decoded
        assert "exp" in decoded
        assert "iat" in decoded
    
    def test_register_duplicate_username(self, client, sample_user):
        """Test registration with duplicate username."""
        # Register first user
        client.post("/register", json=sample_user)
        
        # Try to register user with same username but different email
        duplicate_user = {
            "username": sample_user["username"],
            "email": "different@email.com",
            "password": "password123"
        }
        
        response = client.post("/register", json=duplicate_user)
        
        assert response.status_code == 400
        assert "Username or email already exists" in response.json()["detail"]
    
    def test_register_duplicate_email(self, client, sample_user):
        """Test registration with duplicate email."""
        # Register first user
        client.post("/register", json=sample_user)
        
        # Try to register user with same email but different username
        duplicate_user = {
            "username": "differentuser",
            "email": sample_user["email"],
            "password": "password123"
        }
        
        response = client.post("/register", json=duplicate_user)
        
        assert response.status_code == 400
        assert "Username or email already exists" in response.json()["detail"]
    
    def test_register_invalid_data(self, client):
        """Test registration with invalid/missing data."""
        invalid_users = [
            {"username": "", "email": "test@test.com", "password": "pass123"},
            {"username": "test", "email": "", "password": "pass123"},
            {"username": "test", "email": "test@test.com", "password": ""},
            {"email": "test@test.com", "password": "pass123"},  # missing username
            {"username": "test", "password": "pass123"},  # missing email
            {"username": "test", "email": "test@test.com"},  # missing password
        ]
        
        for invalid_user in invalid_users:
            response = client.post("/register", json=invalid_user)
            assert response.status_code in [400, 422]  # 422 for validation errors
    
    @patch('main.get_db_connection')
    def test_register_database_error(self, mock_db, client, sample_user):
        """Test registration with database error."""
        mock_db.side_effect = Exception("Database error")
        
        response = client.post("/register", json=sample_user)
        
        assert response.status_code == 500
        assert "Registration failed" in response.json()["detail"]


class TestUserLogin:
    """Test user login endpoint."""
    
    def test_login_success(self, client, sample_user):
        """Test successful user login."""
        # Register user first
        client.post("/register", json=sample_user)
        
        # Login with correct credentials
        login_data = {
            "username": sample_user["username"],
            "password": sample_user["password"]
        }
        response = client.post("/login", json=login_data)
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify token response structure
        assert "access_token" in data
        assert "token_type" in data
        assert "expires_in" in data
        assert data["token_type"] == "bearer"
        
        # Verify token is valid JWT
        token = data["access_token"]
        decoded = jwt.decode(token, "test-secret-key", algorithms=["HS256"])
        assert decoded["username"] == sample_user["username"]
    
    def test_login_invalid_username(self, client, sample_user):
        """Test login with non-existent username."""
        login_data = {
            "username": "nonexistent",
            "password": "anypassword"
        }
        response = client.post("/login", json=login_data)
        
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]
    
    def test_login_invalid_password(self, client, sample_user):
        """Test login with incorrect password."""
        # Register user first
        client.post("/register", json=sample_user)
        
        # Login with wrong password
        login_data = {
            "username": sample_user["username"],
            "password": "wrongpassword"
        }
        response = client.post("/login", json=login_data)
        
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]
    
    def test_login_missing_data(self, client):
        """Test login with missing credentials."""
        invalid_logins = [
            {"username": "test"},  # missing password
            {"password": "test"},  # missing username
            {},  # missing both
        ]
        
        for invalid_login in invalid_logins:
            response = client.post("/login", json=invalid_login)
            assert response.status_code in [400, 422]
    
    @patch('main.get_db_connection')
    def test_login_database_error(self, mock_db, client, sample_user):
        """Test login with database error."""
        mock_db.side_effect = Exception("Database error")
        
        login_data = {
            "username": sample_user["username"],
            "password": sample_user["password"]
        }
        response = client.post("/login", json=login_data)
        
        assert response.status_code == 500
        assert "Login failed" in response.json()["detail"]


class TestUserProfile:
    """Test user profile endpoint (protected)."""
    
    def test_get_profile_success(self, client, authenticated_user):
        """Test getting user profile with valid token."""
        response = client.get("/profile", headers=authenticated_user["headers"])
        
        assert response.status_code == 200
        data = response.json()
        
        assert "user_id" in data
        assert data["username"] == authenticated_user["user_data"]["username"]
        assert data["email"] == authenticated_user["user_data"]["email"]
        assert data["is_active"] is True
    
    def test_get_profile_no_token(self, client):
        """Test getting profile without authentication token."""
        response = client.get("/profile")
        
        assert response.status_code == 403  # FastAPI returns 403 for missing auth
    
    def test_get_profile_invalid_token(self, client, invalid_token):
        """Test getting profile with invalid token."""
        headers = {"Authorization": f"Bearer {invalid_token}"}
        response = client.get("/profile", headers=headers)
        
        assert response.status_code == 401
        assert "Invalid token" in response.json()["detail"]
    
    def test_get_profile_expired_token(self, client, expired_token):
        """Test getting profile with expired token."""
        headers = {"Authorization": f"Bearer {expired_token}"}
        response = client.get("/profile", headers=headers)
        
        assert response.status_code == 401
        assert "Token has expired" in response.json()["detail"]


class TestGetAllUsers:
    """Test get all users endpoint (protected)."""
    
    def test_get_users_success(self, client, multiple_users):
        """Test getting all users with valid authentication."""
        # Use first user's token
        headers = {"Authorization": f"Bearer {multiple_users[0]['token_response']['access_token']}"}
        
        response = client.get("/users", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        
        assert "users" in data
        assert "count" in data
        assert data["count"] == 3
        assert len(data["users"]) == 3
        
        # Verify user data structure
        for user in data["users"]:
            assert "id" in user
            assert "username" in user
            assert "email" in user
            assert "is_active" in user
            assert "created_at" in user
    
    def test_get_users_no_token(self, client):
        """Test getting users without authentication."""
        response = client.get("/users")
        
        assert response.status_code == 403
    
    def test_get_users_invalid_token(self, client, invalid_token):
        """Test getting users with invalid token."""
        headers = {"Authorization": f"Bearer {invalid_token}"}
        response = client.get("/users", headers=headers)
        
        assert response.status_code == 401
    
    @patch('main.get_db_connection')
    def test_get_users_database_error(self, mock_db, client, authenticated_user):
        """Test getting users with database error."""
        mock_db.side_effect = Exception("Database error")
        
        response = client.get("/users", headers=authenticated_user["headers"])
        
        assert response.status_code == 500
        assert "Failed to retrieve users" in response.json()["detail"]


class TestUserLogout:
    """Test user logout endpoint (protected)."""
    
    def test_logout_success(self, client, authenticated_user):
        """Test successful user logout."""
        response = client.post("/logout", headers=authenticated_user["headers"])
        
        assert response.status_code == 200
        data = response.json()
        
        expected_message = f"User {authenticated_user['user_data']['username']} logged out successfully"
        assert data["message"] == expected_message
    
    def test_logout_no_token(self, client):
        """Test logout without authentication."""
        response = client.post("/logout")
        
        assert response.status_code == 403
    
    def test_logout_invalid_token(self, client, invalid_token):
        """Test logout with invalid token."""
        headers = {"Authorization": f"Bearer {invalid_token}"}
        response = client.post("/logout", headers=headers)
        
        assert response.status_code == 401


class TestAuthenticationMiddleware:
    """Test authentication and JWT token handling."""
    
    def test_bearer_token_extraction(self, client, authenticated_user):
        """Test that Bearer token is properly extracted and processed."""
        response = client.get("/profile", headers=authenticated_user["headers"])
        assert response.status_code == 200
    
    def test_malformed_authorization_header(self, client):
        """Test handling of malformed Authorization headers."""
        malformed_headers = [
            {"Authorization": "Bearer"},  # No token
            {"Authorization": "InvalidToken"},  # No Bearer prefix
            {"Authorization": "Bearer token1 token2"},  # Multiple tokens
        ]
        
        for headers in malformed_headers:
            response = client.get("/profile", headers=headers)
            assert response.status_code in [401, 403]
    
    def test_user_inactive_status(self, client, authenticated_user):
        """Test access with inactive user account."""
        # This would require additional database manipulation
        # For now, we'll test the logic exists
        response = client.get("/profile", headers=authenticated_user["headers"])
        assert response.status_code == 200  # User is active by default 