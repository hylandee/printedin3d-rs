import pytest
import requests
import sqlite3
import time
import os
from pathlib import Path

BASE_URL = "http://127.0.0.1:3000/api"
DB_PATH = str(Path(__file__).parent.parent / "auth.db")

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
    assert resp.status_code == 201, f"Signup failed: {resp.status_code} - {resp.text}"

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
    if os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        conn.execute("DELETE FROM users WHERE username = ?", (test_user,))
        conn.execute("DELETE FROM users WHERE username = ?", (f"{test_user}_updated",))
        conn.commit()
        conn.close()

@pytest.fixture(scope="function", autouse=True)
def cleanup_after_each_test():
    """Clean up database after each test to prevent state conflicts"""
    yield
    # After each test, clean up any test data
    if os.path.exists(DB_PATH):
        try:
            conn = sqlite3.connect(DB_PATH, timeout=5.0)
            conn.execute("DELETE FROM order_items WHERE order_id IN (SELECT id FROM orders WHERE user_id IN (SELECT id FROM users WHERE username LIKE 'test_%' OR username LIKE 'customer_%' OR username LIKE 'operator_%' OR username LIKE 'admin_%' OR username LIKE 'viewer_%' OR username LIKE 'profile_test_%'))")
            conn.execute("DELETE FROM orders WHERE user_id IN (SELECT id FROM users WHERE username LIKE 'test_%' OR username LIKE 'customer_%' OR username LIKE 'operator_%' OR username LIKE 'admin_%' OR username LIKE 'viewer_%' OR username LIKE 'profile_test_%')")
            conn.execute("DELETE FROM products WHERE name LIKE 'Test%'")
            conn.execute("DELETE FROM filaments WHERE name LIKE 'Test%'")
            conn.execute("DELETE FROM users WHERE username LIKE 'test_%' OR username LIKE 'customer_%' OR username LIKE 'operator_%' OR username LIKE 'admin_%' OR username LIKE 'viewer_%' OR username LIKE 'profile_test_%'")
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Cleanup error: {e}")

@pytest.fixture(scope="session", autouse=True)
def cleanup_session(test_user):
    yield
    # Clean up main test user at end of session
    if os.path.exists(DB_PATH):
        try:
            conn = sqlite3.connect(DB_PATH, timeout=5.0)
            conn.execute("DELETE FROM users WHERE username = ?", (test_user,))
            conn.execute("DELETE FROM users WHERE username = ?", (f"{test_user}_updated",))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Session cleanup error: {e}")

def create_user_with_role(session, username, password, role="Customer"):
    """Helper function to create a user with a specific role"""
    payload = {"username": username, "password": password}

    # Signup
    resp = session.post(f"{BASE_URL}/signup", json=payload)
    assert resp.status_code == 201, f"Signup failed: {resp.status_code} - {resp.text}"

    # Login
    resp = session.post(f"{BASE_URL}/login", json=payload)
    assert resp.status_code == 200

    # If not customer, promote to the desired role (requires admin session)
    if role != "Customer":
        # We need an admin session to change roles
        admin_session = requests.Session()
        admin_payload = {"username": f"admin_{int(time.time() * 1000000)}", "password": "AdminPass123!"}

        # Create admin user
        admin_resp = admin_session.post(f"{BASE_URL}/signup", json=admin_payload)
        assert admin_resp.status_code == 201

        admin_login = admin_session.post(f"{BASE_URL}/login", json=admin_payload)
        assert admin_login.status_code == 200

        # Promote admin user to admin role (this requires another admin, so we'll manually set in DB for testing)
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        conn.execute("UPDATE users SET role = 'Admin' WHERE username = ?", (admin_payload["username"],))
        conn.commit()

        # Now promote the target user to desired role
        user_resp = admin_session.get(f"{BASE_URL}/users")
        assert user_resp.status_code == 200
        users = user_resp.json()

        target_user = next((u for u in users if u["username"] == username), None)
        assert target_user is not None

        update_resp = admin_session.put(f"{BASE_URL}/users/{target_user['id']}/role", json={"role": role})
        assert update_resp.status_code == 200

        # Clean up admin user
        conn.execute("DELETE FROM users WHERE username = ?", (admin_payload["username"],))
        conn.commit()
        conn.close()

    return session

def test_role_based_product_creation(session):
    """Test that operators can create products but customers cannot"""
    customer_username = f"customer_{int(time.time() * 1000000)}"
    operator_username = f"operator_{int(time.time() * 1000000)}"

    # Create customer session
    customer_session = requests.Session()
    customer_session = create_user_with_role(customer_session, customer_username, "Password123!", "Customer")

    # Create operator session
    operator_session = requests.Session()
    operator_session = create_user_with_role(operator_session, operator_username, "Password123!", "Operator")

    product_payload = {
        "name": "Test Product",
        "description": "A test product",
        "base_price": 25.99,
        "image_url": "https://example.com/test.jpg"
    }

    # Customer should not be able to create products
    resp = customer_session.post(f"{BASE_URL}/products", json=product_payload)
    assert resp.status_code == 401  # Unauthorized

    # Operator should be able to create products
    resp = operator_session.post(f"{BASE_URL}/products", json=product_payload)
    assert resp.status_code == 200
    product_data = resp.json()
    assert product_data["name"] == "Test Product"
    assert product_data["base_price"] == 25.99

    # Clean up
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.execute("DELETE FROM users WHERE username = ?", (customer_username,))
    conn.execute("DELETE FROM users WHERE username = ?", (operator_username,))
    conn.execute("DELETE FROM products WHERE name = ?", ("Test Product",))
    conn.commit()
    conn.close()

def test_role_based_filament_creation(session):
    """Test that operators can create filaments but customers cannot"""
    customer_username = f"customer_{int(time.time() * 1000000)}"
    operator_username = f"operator_{int(time.time() * 1000000)}"

    # Create customer session
    customer_session = requests.Session()
    customer_session = create_user_with_role(customer_session, customer_username, "Password123!", "Customer")

    # Create operator session
    operator_session = requests.Session()
    operator_session = create_user_with_role(operator_session, operator_username, "Password123!", "Operator")

    filament_payload = {
        "name": "Test Filament",
        "surcharge": 2.50,
        "image_url": "https://example.com/test-filament.jpg"
    }

    # Customer should not be able to create filaments
    resp = customer_session.post(f"{BASE_URL}/filaments", json=filament_payload)
    assert resp.status_code == 401  # Unauthorized

    # Operator should be able to create filaments
    resp = operator_session.post(f"{BASE_URL}/filaments", json=filament_payload)
    assert resp.status_code == 200
    filament_data = resp.json()
    assert filament_data["name"] == "Test Filament"
    assert filament_data["surcharge"] == 2.50

    # Clean up
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.execute("DELETE FROM users WHERE username = ?", (customer_username,))
    conn.execute("DELETE FROM users WHERE username = ?", (operator_username,))
    conn.execute("DELETE FROM filaments WHERE name = ?", ("Test Filament",))
    conn.commit()
    conn.close()

def test_queue_manipulation_by_role(session):
    """Test that operators can manipulate queue but customers cannot"""
    customer_username = f"customer_{int(time.time() * 1000000)}"
    operator_username = f"operator_{int(time.time() * 1000000)}"

    # Create customer session
    customer_session = requests.Session()
    customer_session = create_user_with_role(customer_session, customer_username, "Password123!", "Customer")

    # Create operator session
    operator_session = requests.Session()
    operator_session = create_user_with_role(operator_session, operator_username, "Password123!", "Operator")

    # Create a test order first (this would normally be done by a customer)
    # For this test, we'll manually insert an order into the database
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    cursor = conn.cursor()

    # Get customer user ID
    cursor.execute("SELECT id FROM users WHERE username = ?", (customer_username,))
    customer_id = cursor.fetchone()[0]

    # Insert a test order
    cursor.execute("""
        INSERT INTO orders (user_id, status, total_amount, queue_position, created_at, updated_at)
        VALUES (?, 'in_queue', 50.00, 1, ?, ?)
    """, (customer_id, time.time(), time.time()))
    order_id = cursor.lastrowid

    conn.commit()
    conn.close()

    # Customer should not be able to manipulate queue
    resp = customer_session.put(f"{BASE_URL}/orders/{order_id}/queue/move-up")
    assert resp.status_code == 401  # Unauthorized

    resp = customer_session.put(f"{BASE_URL}/orders/{order_id}/queue/move-down")
    assert resp.status_code == 401  # Unauthorized

    # Operator should be able to manipulate queue (even though there's only one order)
    resp = operator_session.put(f"{BASE_URL}/orders/{order_id}/queue/move-up")
    assert resp.status_code == 200  # OK (no-op since it's already first)

    resp = operator_session.put(f"{BASE_URL}/orders/{order_id}/queue/move-down")
    assert resp.status_code == 200  # OK (no-op since it's already last)

    # Clean up
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.execute("DELETE FROM users WHERE username = ?", (customer_username,))
    conn.execute("DELETE FROM users WHERE username = ?", (operator_username,))
    conn.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()

def test_get_products_and_filaments(session):
    """Test that all authenticated users can view products and filaments"""
    test_username = f"viewer_{int(time.time() * 1000000)}"

    # Create user session
    user_session = requests.Session()
    user_session = create_user_with_role(user_session, test_username, "Password123!", "Customer")

    # Should be able to get products
    resp = user_session.get(f"{BASE_URL}/products")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # Should be able to get filaments
    resp = user_session.get(f"{BASE_URL}/filaments")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # Clean up
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.execute("DELETE FROM users WHERE username = ?", (test_username,))
    conn.commit()
    conn.close()