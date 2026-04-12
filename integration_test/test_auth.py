import pytest
import requests
import sqlite3
import time
import os

BASE_URL = "http://127.0.0.1:3000"

@pytest.fixture(scope="session")
def test_user():
    return f"test_user_{int(time.time() * 1000000)}"

@pytest.fixture(scope="session")
def session():
    return requests.Session()

def test_full_auth_flow(test_user, session):
    payload = {"username": test_user, "password": "Password123!"}

    # Signup
    resp = session.post(f"{BASE_URL}/signup", json=payload)
    assert resp.status_code == 201

    # Duplicate signup should fail
    resp = session.post(f"{BASE_URL}/signup", json=payload)
    assert resp.status_code == 409

    # Login
    resp = session.post(f"{BASE_URL}/login", json=payload)
    assert resp.status_code == 200

    # Get user info
    resp = session.get(f"{BASE_URL}/me")
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == test_user

    # Logout
    resp = session.post(f"{BASE_URL}/logout")
    assert resp.status_code == 204

    # /me should fail after logout
    resp = session.get(f"{BASE_URL}/me")
    assert resp.status_code == 401

    # Bad login
    bad_payload = {"username": test_user, "password": "WrongPassword123!"}
    resp = session.post(f"{BASE_URL}/login", json=bad_payload)
    assert resp.status_code == 401

def test_input_validation(session):
    # Test invalid username (too short)
    resp = session.post(f"{BASE_URL}/signup", json={"username": "ab", "password": "Password123!"})
    assert resp.status_code == 400
    assert "username must be at least 3 characters" in resp.text

    # Test invalid username (invalid characters)
    resp = session.post(f"{BASE_URL}/signup", json={"username": "test@user", "password": "Password123!"})
    assert resp.status_code == 400
    assert "username can only contain" in resp.text

    # Test invalid password (too short)
    resp = session.post(f"{BASE_URL}/signup", json={"username": "validuser123", "password": "short"})
    assert resp.status_code == 400
    assert "password must be at least 8 characters" in resp.text

    # Test invalid password (no uppercase)
    resp = session.post(f"{BASE_URL}/signup", json={"username": "validuser123", "password": "password123!"})
    assert resp.status_code == 400
    assert "password must contain at least one uppercase letter" in resp.text

    # Test invalid password (no lowercase)
    resp = session.post(f"{BASE_URL}/signup", json={"username": "validuser123", "password": "PASSWORD123!"})
    assert resp.status_code == 400
    assert "password must contain at least one lowercase letter" in resp.text

    # Test invalid password (no non-alpha)
    resp = session.post(f"{BASE_URL}/signup", json={"username": "validuser123", "password": "PasswordOnly"})
    assert resp.status_code == 400
    assert "password must contain at least one non-alphabetic character" in resp.text

    # Test invalid login credentials (should still validate)
    resp = session.post(f"{BASE_URL}/login", json={"username": "ab", "password": "Password123!"})
    assert resp.status_code == 400

def test_profile_management(session):
    test_user = f"profile_test_user_{int(time.time() * 1000000)}"
    payload = {"username": test_user, "password": "Password123!"}

    # Signup and login first
    resp = session.post(f"{BASE_URL}/signup", json=payload)
    assert resp.status_code == 201

    resp = session.post(f"{BASE_URL}/login", json=payload)
    assert resp.status_code == 200

    # Test get profile
    resp = session.get(f"{BASE_URL}/profile")
    assert resp.status_code == 200
    profile_data = resp.json()
    assert profile_data["username"] == test_user
    assert "id" in profile_data
    assert "created_at" in profile_data

    # Test change password
    change_payload = {"current_password": "Password123!", "new_password": "NewPassword456!"}
    resp = session.post(f"{BASE_URL}/change-password", json=change_payload)
    assert resp.status_code == 200

    # Verify old password no longer works
    resp = session.post(f"{BASE_URL}/login", json=payload)
    assert resp.status_code == 401

    # Login with new password
    new_login = {"username": test_user, "password": "NewPassword456!"}
    resp = session.post(f"{BASE_URL}/login", json=new_login)
    assert resp.status_code == 200

    # Test update username
    update_payload = {"new_username": f"{test_user}_updated"}
    resp = session.post(f"{BASE_URL}/update-username", json=update_payload)
    assert resp.status_code == 200

    # Verify profile shows new username
    resp = session.get(f"{BASE_URL}/profile")
    assert resp.status_code == 200
    profile_data = resp.json()
    assert profile_data["username"] == f"{test_user}_updated"

    # Test change password with wrong current password
    bad_change = {"current_password": "WrongPassword!", "new_password": "AnotherPassword789!"}
    resp = session.post(f"{BASE_URL}/change-password", json=bad_change)
    assert resp.status_code == 401

    # Clean up this test's users
    if os.path.exists("../auth.db"):
        conn = sqlite3.connect("../auth.db")
        conn.execute("DELETE FROM users WHERE username = ?", (test_user,))
        conn.execute("DELETE FROM users WHERE username = ?", (f"{test_user}_updated",))
        conn.commit()
        conn.close()

@pytest.fixture(scope="session", autouse=True)
def cleanup(test_user):
    yield
    # Clean up test user from DB
    if os.path.exists("../auth.db"):
        conn = sqlite3.connect("../auth.db")
        conn.execute("DELETE FROM users WHERE username = ?", (test_user,))
        conn.execute("DELETE FROM users WHERE username = ?", (f"{test_user}_updated",))
        conn.commit()
        conn.close()