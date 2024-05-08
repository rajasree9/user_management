from builtins import str
import pytest
from httpx import AsyncClient
from app.main import app
from app.models.user_model import User, UserRole
from app.utils.nickname_gen import generate_nickname
from app.utils.security import hash_password
from app.services.jwt_service import decode_token  # Import your FastAPI app

# Example of a test function using the async_client fixture
@pytest.mark.asyncio
async def test_create_user_access_denied(async_client, user_token, email_service):
    headers = {"Authorization": f"Bearer {user_token}"}
    # Define user data for the test
    user_data = {
        "nickname": generate_nickname(),
        "email": "test@example.com",
        "password": "sS#fdasrongPassword123!",
    }
    # Send a POST request to create a user
    response = await async_client.post("/users/", json=user_data, headers=headers)
    # Asserts
    assert response.status_code == 403

# You can similarly refactor other test functions to use the async_client fixture
@pytest.mark.asyncio
async def test_retrieve_user_access_denied(async_client, verified_user, user_token):
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.get(f"/users/{verified_user.id}", headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_retrieve_user_access_allowed(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == str(admin_user.id)

@pytest.mark.asyncio
async def test_update_user_email_access_denied(async_client, verified_user, user_token):
    updated_data = {"email": f"updated_{verified_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_update_user_email_access_allowed(async_client, admin_user, admin_token):
    updated_data = {"email": f"updated_{admin_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == updated_data["email"]

@pytest.mark.asyncio
async def test_update_user_email_conflict(async_client, admin_user, verified_user, admin_token):
    """
    Test to ensure that updating a user's email to an email that already exists is not allowed and returns an appropriate error.
    This test first updates an admin user's email and then tries to set the same email for a different verified user.
    """
    # Set new email for the admin user
    updated_email_data = {"email": f"updated_{admin_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    await async_client.put(f"/users/{admin_user.id}", json=updated_email_data, headers=headers)
    
    # Attempt to update a verified user's email to the same email address
    conflict_response = await async_client.put(f"/users/{verified_user.id}", json=updated_email_data, headers=headers)
    
    # Assert that the response indicates the email already exists
    assert "email already exists" in conflict_response.json().get("detail", ""), \
        "The API should prevent setting duplicate email addresses and should return a relevant error message."

@pytest.mark.asyncio

    """
    Test to verify that updating a user's email address is idempotent.
    This involves updating the email address to the same value twice and checking that both requests succeed without errors.
    """
    # Update email for the first time
    update_data = {"email": f"updated_{admin_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    initial_response = await async_client.put(f"/users/{admin_user.id}", json=update_data, headers=headers)
    assert initial_response.status_code == 200, "The first email update should succeed."

    # Repeat the update with the same email
    repeat_response = await async_client.put(f"/users/{admin_user.id}", json=update_data, headers=headers)
    assert repeat_response.status_code == 200, "The second update with the same email should also succeed, confirming idempotence."

@pytest.mark.asyncio
async def test_delete_user(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{admin_user.id}", headers=headers)
    assert delete_response.status_code == 204
    # Verify the user is deleted
    fetch_response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert fetch_response.status_code == 404

@pytest.mark.asyncio
async def test_create_user_duplicate_email(async_client, verified_user):
    user_data = {
        "email": verified_user.email,
        "password": "AnotherPassword123!",
        "role": UserRole.ADMIN.name
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 400
    assert "Email already exists" in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_create_user_with_linkedin_url_tc4(async_client, verified_user):
    """
    Test the successful creation of a user with a specified LinkedIn URL.
    Ensures that the user is created with the correct LinkedIn URL in their profile.
    """
    user_data = {
        "email": "john12_linkedin@example.com",  # Unique email to avoid conflicts
        "password": "AnotherPassword123!",
        "role": UserRole.ADMIN.name,
        "linkedin_profile_url": "https://linkedin.com/in/johndoe",
        "github_profile_url": "https://github.com/johndoe"
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 201, "Expected successful creation with status code 201"
    assert response.json().get("linkedin_profile_url") == "https://linkedin.com/in/johndoe", \
        "The LinkedIn URL in the response should match the one provided"

@pytest.mark.asyncio
async def test_create_user_with_github_url_tc5(async_client, verified_user):
    """
    Test the successful creation of a user with a specified GitHub URL.
    Verifies that the user's GitHub URL is correctly set during registration.
    """
    user_data = {
        "email": "john12_github@example.com",  # Unique email to ensure no duplication
        "password": "AnotherPassword123!",
        "role": UserRole.ADMIN.name,
        "linkedin_profile_url": "https://linkedin.com/in/johndoe",
        "github_profile_url": "https://github.com/johndoe"
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 201, "Expected successful creation with status code 201"
    assert response.json().get("github_profile_url") == "https://github.com/johndoe", \
        "The GitHub URL in the response should match the one provided"
    
@pytest.mark.asyncio
async def test_create_user_invalid_linkedin_url(async_client):
    user_data = {
        "email": "testuser@example.com",
        "password": "ValidPassword123!",
        "role": "USER",
        "linkedin_profile_url": "invalid_linkedin_url",  # Invalid URL
        "github_profile_url": "https://github.com/testuser"
    }
    response = await async_client.post("/register/", json=user_data)
    
    # The server should return a 400 Bad Request response due to invalid LinkedIn URL
    assert response.status_code == 400, "Invalid LinkedIn URL should return 400 Bad Request."

@pytest.mark.asyncio
async def test_create_user_invalid_github_url(async_client):
    user_data = {
        "email": "testuser@example.com",
        "password": "ValidPassword123!",
        "role": "USER",
        "linkedin_profile_url": "https://linkedin.com/in/testuser",
        "github_profile_url": "invalid_github_url"  # Invalid URL
    }
    response = await async_client.post("/register/", json=user_data)
    
    # The server should return a 400 Bad Request response due to invalid GitHub URL
    assert response.status_code == 400, "Invalid GitHub URL should return 400 Bad Request."


@pytest.mark.asyncio
async def test_create_user_invalid_email(async_client):
    user_data = {
        "email": "notanemail",
        "password": "ValidPassword123!",
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 422

import pytest
from app.services.jwt_service import decode_token
from urllib.parse import urlencode

@pytest.mark.asyncio
async def test_login_success(async_client, verified_user):
    # Attempt to login with the test user
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    
    # Check for successful login response
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Use the decode_token method from jwt_service to decode the JWT
    decoded_token = decode_token(data["access_token"])
    assert decoded_token is not None, "Failed to decode token"
    assert decoded_token["role"] == "AUTHENTICATED", "The user role should be AUTHENTICATED"

@pytest.mark.asyncio
async def test_login_user_not_found(async_client):
    form_data = {
        "username": "nonexistentuser@here.edu",
        "password": "DoesNotMatter123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_incorrect_password(async_client, verified_user):
    form_data = {
        "username": verified_user.email,
        "password": "IncorrectPassword123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_unverified_user(async_client, unverified_user):
    form_data = {
        "username": unverified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_login_locked_user(async_client, locked_user):
    form_data = {
        "username": locked_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 400
    assert "Account locked due to too many failed login attempts." in response.json().get("detail", "")
@pytest.mark.asyncio
async def test_delete_user_does_not_exist(async_client, admin_token):
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"  # Valid UUID format
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{non_existent_user_id}", headers=headers)
    assert delete_response.status_code == 404

@pytest.mark.asyncio
async def test_update_user_github(async_client, admin_user, admin_token):
    updated_data = {"github_profile_url": "http://www.github.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["github_profile_url"] == updated_data["github_profile_url"]

@pytest.mark.asyncio
async def test_update_user_linkedin(async_client, admin_user, admin_token):
    updated_data = {"linkedin_profile_url": "http://www.linkedin.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["linkedin_profile_url"] == updated_data["linkedin_profile_url"]

@pytest.mark.asyncio
async def test_list_users_as_admin(async_client, admin_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert 'items' in response.json()

@pytest.mark.asyncio
async def test_list_users_as_manager(async_client, manager_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_list_users_unauthorized(async_client, user_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403  # Forbidden, as expected for regular user