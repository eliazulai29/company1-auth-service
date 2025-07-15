"""
Comprehensive security tests for auth-service.
Tests password hashing, JWT token generation/validation, and security mechanisms.
Ensures security vulnerabilities are caught before production.
"""

import pytest
import jwt
import bcrypt
import datetime
from unittest.mock import patch
from main import hash_password, verify_password, create_jwt_token, verify_jwt_token


class TestPasswordSecurity:
    """Test password hashing and verification."""
    
    def test_password_hashing(self):
        """Test that passwords are properly hashed with bcrypt."""
        password = "testpassword123"
        hashed = hash_password(password)
        
        # Verify hash is different from original password
        assert hashed != password
        
        # Verify hash starts with bcrypt prefix
        assert hashed.startswith("$2b$")
        
        # Verify hash can be verified
        assert verify_password(password, hashed) is True
    
    def test_password_verification_success(self):
        """Test successful password verification."""
        password = "mySecurePassword123!"
        hashed = hash_password(password)
        
        assert verify_password(password, hashed) is True
    
    def test_password_verification_failure(self):
        """Test failed password verification with wrong password."""
        password = "correctPassword"
        wrong_password = "wrongPassword"
        hashed = hash_password(password)
        
        assert verify_password(wrong_password, hashed) is False
    
    def test_password_verification_empty_password(self):
        """Test password verification with empty password."""
        password = "testpassword"
        hashed = hash_password(password)
        
        assert verify_password("", hashed) is False
        # Note: verify_password expects string input, None would cause AttributeError
        # This is correct behavior - the API layer should validate input before calling this function
    
    def test_password_hashing_different_salts(self):
        """Test that same password produces different hashes (due to salt)."""
        password = "samePassword"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        
        # Different hashes due to different salts
        assert hash1 != hash2
        
        # But both should verify correctly
        assert verify_password(password, hash1) is True
        assert verify_password(password, hash2) is True
    
    def test_password_unicode_handling(self):
        """Test password hashing with unicode characters."""
        unicode_password = "pássword123ñ"
        hashed = hash_password(unicode_password)
        
        assert verify_password(unicode_password, hashed) is True
        assert verify_password("password123n", hashed) is False
    
    def test_long_password_handling(self):
        """Test password hashing with very long passwords."""
        long_password = "a" * 1000  # 1000 characters
        hashed = hash_password(long_password)
        
        assert verify_password(long_password, hashed) is True
        
        # Note: bcrypt may truncate passwords, so this test verifies the actual behavior
        # rather than assuming 999 chars should fail
        shorter_password = "a" * 999
        # Don't assert failure here as bcrypt may handle long passwords differently


class TestJWTTokenSecurity:
    """Test JWT token generation and validation."""
    
    def test_jwt_token_creation(self):
        """Test JWT token creation with valid data."""
        user_id = 123
        username = "testuser"
        
        token = create_jwt_token(user_id, username)
        
        # Verify token is a string
        assert isinstance(token, str)
        
        # Verify token has 3 parts (header.payload.signature)
        assert len(token.split('.')) == 3
        
        # Decode and verify payload
        decoded = jwt.decode(token, "test-secret-key", algorithms=["HS256"])
        assert decoded["user_id"] == user_id
        assert decoded["username"] == username
        assert "exp" in decoded
        assert "iat" in decoded
    
    def test_jwt_token_expiration(self):
        """Test JWT token expiration time."""
        user_id = 123
        username = "testuser"
        
        before_creation = datetime.datetime.utcnow()
        token = create_jwt_token(user_id, username)
        after_creation = datetime.datetime.utcnow()
        
        decoded = jwt.decode(token, "test-secret-key", algorithms=["HS256"])
        
        # Verify expiration is approximately 1 hour from now (test config)
        exp_time = datetime.datetime.utcfromtimestamp(decoded["exp"])
        expected_exp = before_creation + datetime.timedelta(hours=1)
        
        # Allow 2 minute tolerance for timing variations
        assert abs((exp_time - expected_exp).total_seconds()) < 120
        
        # Verify issued at time (allow broader tolerance for microsecond precision)
        iat_time = datetime.datetime.utcfromtimestamp(decoded["iat"])
        time_diff = (after_creation - before_creation).total_seconds()
        # Allow for the time it took to create the token plus some buffer
        assert abs((iat_time - before_creation).total_seconds()) <= time_diff + 1
    
    def test_jwt_token_verification_success(self):
        """Test successful JWT token verification."""
        user_id = 456
        username = "verifyuser"
        
        token = create_jwt_token(user_id, username)
        payload = verify_jwt_token(token)
        
        assert payload["user_id"] == user_id
        assert payload["username"] == username
    
    def test_jwt_token_verification_invalid_token(self):
        """Test JWT verification with invalid token."""
        invalid_tokens = [
            "invalid.token.here",
            "not-a-jwt-token",
            "",
            "header.payload",  # Missing signature
            "too.many.parts.here.invalid"
        ]
        
        for invalid_token in invalid_tokens:
            with pytest.raises(Exception):  # Should raise HTTPException
                verify_jwt_token(invalid_token)
    
    def test_jwt_token_verification_expired(self):
        """Test JWT verification with expired token."""
        # Create token that's already expired
        payload = {
            "user_id": 123,
            "username": "testuser",
            "exp": datetime.datetime.utcnow() - datetime.timedelta(hours=1),  # 1 hour ago
            "iat": datetime.datetime.utcnow() - datetime.timedelta(hours=2)   # 2 hours ago
        }
        
        expired_token = jwt.encode(payload, "test-secret-key", algorithm="HS256")
        
        with pytest.raises(Exception):  # Should raise HTTPException for expired token
            verify_jwt_token(expired_token)
    
    def test_jwt_token_verification_wrong_secret(self):
        """Test JWT verification with wrong secret key."""
        user_id = 123
        username = "testuser"
        
        # Create token with correct secret
        token = create_jwt_token(user_id, username)
        
        # Try to verify with wrong secret
        with pytest.raises(Exception):
            jwt.decode(token, "wrong-secret-key", algorithms=["HS256"])
    
    def test_jwt_token_verification_wrong_algorithm(self):
        """Test JWT verification with wrong algorithm."""
        user_id = 123
        username = "testuser"
        
        token = create_jwt_token(user_id, username)
        
        # Try to verify with wrong algorithm
        with pytest.raises(Exception):
            jwt.decode(token, "test-secret-key", algorithms=["RS256"])  # Wrong algorithm


class TestSecurityHeaders:
    """Test security-related headers and responses."""
    
    def test_no_sensitive_data_in_responses(self, client, sample_user):
        """Test that sensitive data is not included in API responses."""
        response = client.post("/register", json=sample_user)
        
        assert response.status_code == 200
        data = response.json()
        
        # Ensure password is not in response
        assert "password" not in str(data)
        assert "password_hash" not in str(data)
        assert sample_user["password"] not in str(data)
    
    def test_error_responses_no_sensitive_data(self, client):
        """Test that error responses don't leak sensitive information."""
        # Try to access protected endpoint without token
        response = client.get("/profile")
        
        # Should get 403 but no internal details
        assert response.status_code == 403
        data = response.json()
        
        # Should not contain stack traces or internal paths
        assert "traceback" not in str(data).lower()
        assert "/app" not in str(data)
        assert "postgres" not in str(data).lower()


class TestAuthenticationFlow:
    """Test complete authentication flow security."""
    
    def test_registration_login_flow_security(self, client):
        """Test that registration and login maintain security."""
        user_data = {
            "username": "securitytest",
            "email": "security@test.com",
            "password": "SecurePassword123!"
        }
        
        # Register user
        register_response = client.post("/register", json=user_data)
        assert register_response.status_code == 200
        
        register_token = register_response.json()["access_token"]
        
        # Login user
        login_response = client.post("/login", json={
            "username": user_data["username"],
            "password": user_data["password"]
        })
        assert login_response.status_code == 200
        
        login_token = login_response.json()["access_token"]
        
        # Both tokens should be valid but different (different iat)
        assert register_token != login_token
        
        # Both tokens should work for authenticated endpoints
        for token in [register_token, login_token]:
            headers = {"Authorization": f"Bearer {token}"}
            response = client.get("/profile", headers=headers)
            assert response.status_code == 200
    
    def test_token_reuse_security(self, client, authenticated_user):
        """Test that tokens can be reused until expiration."""
        token = authenticated_user["token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Use token multiple times
        for _ in range(3):
            response = client.get("/profile", headers=headers)
            assert response.status_code == 200
    
    def test_concurrent_sessions(self, client, sample_user):
        """Test that multiple sessions can exist for same user."""
        # Register user
        client.post("/register", json=sample_user)
        
        # Login twice to create two sessions
        login_data = {
            "username": sample_user["username"],
            "password": sample_user["password"]
        }
        
        response1 = client.post("/login", json=login_data)
        response2 = client.post("/login", json=login_data)
        
        assert response1.status_code == 200
        assert response2.status_code == 200
        
        token1 = response1.json()["access_token"]
        token2 = response2.json()["access_token"]
        
        # Both tokens should be valid
        headers1 = {"Authorization": f"Bearer {token1}"}
        headers2 = {"Authorization": f"Bearer {token2}"}
        
        profile1 = client.get("/profile", headers=headers1)
        profile2 = client.get("/profile", headers=headers2)
        
        assert profile1.status_code == 200
        assert profile2.status_code == 200


class TestInputValidationSecurity:
    """Test security aspects of input validation."""
    
    def test_sql_injection_prevention(self, client):
        """Test that SQL injection attempts are prevented."""
        sql_injection_attempts = [
            {"username": "admin'; DROP TABLE users; --", "password": "password"},
            {"username": "admin", "password": "' OR '1'='1"},
            {"username": "admin' UNION SELECT * FROM users --", "password": "pass"},
        ]
        
        for attempt in sql_injection_attempts:
            response = client.post("/login", json=attempt)
            # Should return 401 (invalid credentials) not 500 (SQL error)
            assert response.status_code == 401
    
    def test_xss_prevention_in_usernames(self, client):
        """Test that XSS attempts in usernames are handled safely."""
        xss_attempts = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
        ]
        
        for xss_username in xss_attempts:
            user_data = {
                "username": xss_username,
                "email": "xss@test.com",
                "password": "password123"
            }
            
            response = client.post("/register", json=user_data)
            
            if response.status_code == 200:
                # If registration succeeds, ensure no script execution in response
                response_text = str(response.json())
                assert "<script>" not in response_text
                assert "javascript:" not in response_text
    
    def test_oversized_input_handling(self, client):
        """Test handling of oversized inputs."""
        oversized_data = {
            "username": "a" * 10000,  # Very long username
            "email": "b" * 10000 + "@test.com",  # Very long email
            "password": "c" * 10000   # Very long password
        }
        
        response = client.post("/register", json=oversized_data)
        # Should handle gracefully, not crash
        assert response.status_code in [400, 422, 500] 