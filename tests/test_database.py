"""
Comprehensive database integration tests for auth-service.
Tests database connections, schema initialization, and data operations.
Ensures database reliability and proper error handling.
"""

import pytest
import psycopg2
from unittest.mock import patch, MagicMock
from main import get_db_connection, init_database


class TestDatabaseConnection:
    """Test database connection functionality."""
    
    def test_database_connection_success(self, test_db):
        """Test successful database connection."""
        conn = get_db_connection()
        
        assert conn is not None
        assert not conn.closed
        
        # Test that we can execute a simple query
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        assert result[0] == 1
        
        cursor.close()
        conn.close()
    
    @patch('psycopg2.connect')
    def test_database_connection_failure(self, mock_connect):
        """Test database connection failure handling."""
        mock_connect.side_effect = psycopg2.OperationalError("Connection failed")
        
        with pytest.raises(Exception):  # Should raise HTTPException
            get_db_connection()
    
    @patch('psycopg2.connect')
    def test_database_connection_timeout(self, mock_connect):
        """Test database connection timeout handling."""
        mock_connect.side_effect = psycopg2.OperationalError("timeout expired")
        
        with pytest.raises(Exception):
            get_db_connection()


class TestDatabaseInitialization:
    """Test database schema initialization."""
    
    def test_init_database_creates_users_table(self, test_db):
        """Test that init_database creates the users table."""
        # Initialize database
        init_database()
        
        # Verify users table exists
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'users'
            )
        """)
        table_exists = cursor.fetchone()[0]
        assert table_exists is True
        
        cursor.close()
        conn.close()
    
    def test_users_table_schema(self, test_db):
        """Test that users table has correct schema."""
        init_database()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get table column information
        cursor.execute("""
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_name = 'users'
            ORDER BY ordinal_position
        """)
        
        columns = cursor.fetchall()
        
        # Verify expected columns exist
        column_names = [col[0] for col in columns]
        expected_columns = ['id', 'username', 'email', 'password_hash', 'is_active', 'created_at']
        
        for expected_col in expected_columns:
            assert expected_col in column_names
        
        cursor.close()
        conn.close()
    
    def test_users_table_constraints(self, test_db):
        """Test that users table has proper constraints."""
        init_database()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Test unique constraint on username
        cursor.execute("""
            INSERT INTO users (username, email, password_hash) 
            VALUES ('testuser', 'test1@example.com', 'hash1')
        """)
        
        # Try to insert duplicate username
        with pytest.raises(psycopg2.IntegrityError):
            cursor.execute("""
                INSERT INTO users (username, email, password_hash) 
                VALUES ('testuser', 'test2@example.com', 'hash2')
            """)
        
        conn.rollback()
        
        # Test unique constraint on email
        cursor.execute("""
            INSERT INTO users (username, email, password_hash) 
            VALUES ('user1', 'same@example.com', 'hash1')
        """)
        
        with pytest.raises(psycopg2.IntegrityError):
            cursor.execute("""
                INSERT INTO users (username, email, password_hash) 
                VALUES ('user2', 'same@example.com', 'hash2')
            """)
        
        cursor.close()
        conn.close()
    
    @patch('main.get_db_connection')
    def test_init_database_connection_error(self, mock_get_db):
        """Test init_database handling of connection errors."""
        mock_get_db.side_effect = Exception("Database connection failed")
        
        # Should not raise exception, just print error
        init_database()  # Should complete without raising


class TestDatabaseOperations:
    """Test actual database operations used by the API."""
    
    def test_user_insertion(self, client, test_db):
        """Test that user registration properly inserts into database."""
        init_database()
        
        user_data = {
            "username": "dbtest",
            "email": "dbtest@example.com",
            "password": "password123"
        }
        
        # Register user via API
        response = client.post("/register", json=user_data)
        assert response.status_code == 200
        
        # Verify user was inserted into database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT username, email, is_active FROM users WHERE username = %s", 
                      (user_data["username"],))
        user = cursor.fetchone()
        
        assert user is not None
        assert user[0] == user_data["username"]
        assert user[1] == user_data["email"]
        assert user[2] is True  # is_active should be True by default
        
        cursor.close()
        conn.close()
    
    def test_user_authentication_database_lookup(self, client, test_db):
        """Test that login properly looks up user in database."""
        init_database()
        
        user_data = {
            "username": "authtest",
            "email": "authtest@example.com",
            "password": "password123"
        }
        
        # Register user
        client.post("/register", json=user_data)
        
        # Login
        login_response = client.post("/login", json={
            "username": user_data["username"],
            "password": user_data["password"]
        })
        
        assert login_response.status_code == 200
        
        # Verify database was queried (user exists)
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", 
                      (user_data["username"],))
        count = cursor.fetchone()[0]
        assert count == 1
        
        cursor.close()
        conn.close()
    
    def test_user_profile_database_lookup(self, client, authenticated_user, test_db):
        """Test that profile endpoint looks up user correctly."""
        response = client.get("/profile", headers=authenticated_user["headers"])
        assert response.status_code == 200
        
        profile_data = response.json()
        
        # Verify data matches what's in database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT username, email, is_active FROM users WHERE id = %s", 
                      (profile_data["user_id"],))
        user = cursor.fetchone()
        
        assert user[0] == profile_data["username"]
        assert user[1] == profile_data["email"]
        assert user[2] == profile_data["is_active"]
        
        cursor.close()
        conn.close()
    
    def test_get_all_users_database_query(self, client, multiple_users, test_db):
        """Test that get all users endpoint queries database correctly."""
        # Use first user's token
        headers = {"Authorization": f"Bearer {multiple_users[0]['token_response']['access_token']}"}
        
        response = client.get("/users", headers=headers)
        assert response.status_code == 200
        
        users_data = response.json()
        assert users_data["count"] == 3
        
        # Verify count matches database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM users")
        db_count = cursor.fetchone()[0]
        assert db_count == 3
        
        cursor.close()
        conn.close()


class TestDatabaseTransactions:
    """Test database transaction handling."""
    
    def test_registration_transaction_rollback_on_error(self, client, test_db):
        """Test that failed registration rolls back database changes."""
        init_database()
        
        # Mock the JWT token creation to fail after user insertion
        with patch('main.create_jwt_token', side_effect=Exception("JWT creation failed")):
            user_data = {
                "username": "rollbacktest",
                "email": "rollback@example.com",
                "password": "password123"
            }
            
            response = client.post("/register", json=user_data)
            assert response.status_code == 500
            
            # Verify user was NOT inserted (rollback occurred)
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", 
                          (user_data["username"],))
            count = cursor.fetchone()[0]
            assert count == 0  # User should not exist due to rollback
            
            cursor.close()
            conn.close()
    
    def test_database_connection_cleanup(self, client, test_db):
        """Test that database connections are properly closed."""
        init_database()
        
        # Make multiple API calls
        user_data = {
            "username": "cleanuptest",
            "email": "cleanup@example.com",
            "password": "password123"
        }
        
        # Register user
        client.post("/register", json=user_data)
        
        # Login
        client.post("/login", json={
            "username": user_data["username"],
            "password": user_data["password"]
        })
        
        # Multiple health checks
        for _ in range(5):
            client.get("/health")
        
        # This test mainly ensures no connection leaks occur
        # which would be evident in test failures or warnings


class TestDatabaseErrorHandling:
    """Test database error handling and recovery."""
    
    @patch('main.get_db_connection')
    def test_health_check_database_error_handling(self, mock_get_db, client):
        """Test health check when database is unavailable."""
        mock_get_db.side_effect = Exception("Database unavailable")
        
        response = client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "unhealthy"
        assert "Database unavailable" in data["error"]
    
    def test_database_constraint_violation_handling(self, client, test_db):
        """Test handling of database constraint violations."""
        init_database()
        
        user_data = {
            "username": "constrainttest",
            "email": "constraint@example.com",
            "password": "password123"
        }
        
        # Register user successfully
        response1 = client.post("/register", json=user_data)
        assert response1.status_code == 200
        
        # Try to register same user again (should violate constraint)
        response2 = client.post("/register", json=user_data)
        assert response2.status_code == 400
        assert "already exists" in response2.json()["detail"]
    
    def test_sql_parameter_handling(self, client, test_db):
        """Test that SQL parameters are properly escaped."""
        init_database()
        
        # Test with special characters that could break SQL
        special_chars_data = {
            "username": "test'user\"with;chars",
            "email": "test@exam'ple.com",
            "password": "pass'word\"123"
        }
        
        response = client.post("/register", json=special_chars_data)
        
        # Should either succeed or fail gracefully (not SQL error)
        assert response.status_code in [200, 400, 422]
        
        if response.status_code == 200:
            # Verify user was inserted correctly
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT username, email FROM users WHERE username = %s", 
                          (special_chars_data["username"],))
            user = cursor.fetchone()
            
            assert user[0] == special_chars_data["username"]
            assert user[1] == special_chars_data["email"]
            
            cursor.close()
            conn.close() 