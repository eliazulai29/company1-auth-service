import datetime
import os

import bcrypt
import jwt
import psycopg2
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel

# Load environment variables from .env file
load_dotenv()

app = FastAPI(title="Auth Service", version="1.0.0")

# Security
security = HTTPBearer()

# JWT Configuration
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-here")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "24"))


# Database connection
def get_db_connection():
    try:
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST", "postgres-postgresql"),
            database=os.getenv("DB_NAME", "postgres"),
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", "mysecurepass"),
        )
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        raise HTTPException(status_code=500, detail="Database connection failed")


# Initialize database
def init_database():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Create users table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(100) NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        # Create sessions table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user_sessions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                token_hash VARCHAR(100) NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        conn.commit()
        cursor.close()
        conn.close()
        print("Auth database initialized successfully")
    except Exception as e:
        print(f"Database initialization error: {e}")


# Pydantic models
class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


# Helper functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def create_jwt_token(user_id: int, username: str) -> str:
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRE_HOURS),
        "iat": datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_jwt_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Dependencies
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = verify_jwt_token(token)

    # Verify user exists and is active
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute(
        "SELECT id, username, email, is_active FROM users WHERE id = %s",
        (payload["user_id"],),
    )
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user or not user["is_active"]:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    return user


# Routes
@app.get("/")
def read_root():
    return {
        "service": "Auth Service",
        "status": "running",
        "version": "1.0.0",
        "database": "connected",
    }


@app.get("/health")
def health_check():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


@app.post("/register", response_model=TokenResponse)
def register_user(user_data: UserCreate):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    try:
        # Check if username or email already exists
        cursor.execute(
            "SELECT id FROM users WHERE username = %s OR email = %s",
            (user_data.username, user_data.email),
        )
        if cursor.fetchone():
            raise HTTPException(
                status_code=400, detail="Username or email already exists"
            )

        # Hash password and create user
        password_hash = hash_password(user_data.password)
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id",
            (user_data.username, user_data.email, password_hash),
        )
        user_id = cursor.fetchone()["id"]

        # Create JWT token
        token = create_jwt_token(user_id, user_data.username)

        conn.commit()
        cursor.close()
        conn.close()

        return TokenResponse(
            access_token=token, token_type="bearer", expires_in=JWT_EXPIRE_HOURS * 3600
        )

    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()


@app.post("/login", response_model=TokenResponse)
def login_user(login_data: UserLogin):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    try:
        # Get user by username
        cursor.execute(
            "SELECT id, username, password_hash, is_active FROM users WHERE username = %s",
            (login_data.username,),
        )
        user = cursor.fetchone()

        if not user or not user["is_active"]:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Verify password
        if not verify_password(login_data.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Create JWT token
        token = create_jwt_token(user["id"], user["username"])

        cursor.close()
        conn.close()

        return TokenResponse(
            access_token=token, token_type="bearer", expires_in=JWT_EXPIRE_HOURS * 3600
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")
    finally:
        cursor.close()
        conn.close()


@app.get("/profile")
def get_user_profile(current_user: dict = Depends(get_current_user)):
    return {
        "user_id": current_user["id"],
        "username": current_user["username"],
        "email": current_user["email"],
        "is_active": current_user["is_active"],
    }


@app.get("/users")
def get_all_users(current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    try:
        cursor.execute(
            "SELECT id, username, email, is_active, created_at FROM users ORDER BY created_at DESC"
        )
        users = cursor.fetchall()

        cursor.close()
        conn.close()

        return {"users": [dict(user) for user in users], "count": len(users)}
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve users: {str(e)}"
        )
    finally:
        cursor.close()
        conn.close()


@app.post("/logout")
def logout_user(current_user: dict = Depends(get_current_user)):
    # In a real implementation, you might want to blacklist the token
    return {"message": f"User {current_user['username']} logged out successfully"}


# Startup event
@app.on_event("startup")
def startup_event():
    init_database()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
