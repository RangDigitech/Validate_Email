# Task: Fix Login and Signup Endpoint Form Parsing

## Detailed Steps to Complete:

1. **Update /register endpoint in main.py**  
   - Change from Pydantic UserCreate model to Form fields: first_name, last_name, email, password.  
   - Validate required fields.  
   - Check email uniqueness.  
   - Hash password and create user in database.  
   - Return user data on success.

2. **Update /login endpoint in main.py**  
   - Change from OAuth2PasswordRequestForm to Form fields: email, password.  
   - Query user by email.  
   - Verify password.  
   - Return access token on success.

3. **Test the endpoints**  
   - Start the FastAPI server.  
   - Use curl or Postman to test /register and /login with form data.  
   - Verify frontend integration works without errors.

## Progress:
- [x] Step 1: Update /register endpoint
- [x] Step 2: Update /login endpoint
- [ ] Step 3: Test endpoints
