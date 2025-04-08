# TypeORM Identity Demo

This is a demonstration of TypeORM Identity, a lightweight, flexible identity management solution for TypeORM-based applications.

## What is TypeORM Identity?

TypeORM Identity provides essential features for user authentication, registration, and management with a focus on security and scalability. It's designed to be easily integrated into any TypeORM-based application.

## Features

- **User Authentication**: Handles user login and session management
- **Role-based Access Control (RBAC)**: Define roles and permissions for different user types
- **Password Hashing**: Securely stores user passwords using bcrypt hashing
- **JWT-based Authentication**: Easy integration with JWT for stateless authentication
- **Email Verification**: Provides email verification flow during registration
- **Forgot Password Flow**: Allows users to reset passwords securely

## Project Architecture

TypeORM Identity follows a clean architecture approach:

1. **Domain Layer**:
   - Core entities: Users, Roles, Claims
   - Domain models and interfaces

2. **Infrastructure Layer**:
   - User Manager: Handles user operations like registration, password management
   - Role Manager: Manages roles and permissions
   - Authentication: Handles sign-in and security

3. **Configuration**:
   - Flexible options for password policies, lockout, and user validation

## How to Use

1. Create user and role entities that extend the base TypeORM Identity entities
2. Configure TypeORM Identity with your desired settings
3. Connect it to your TypeORM data source
4. Use the provided managers to handle user and role operations

## Example

```typescript
// Initialize TypeORM Identity
const { container } = AddIdentity<MyUser, MyRole>((options) => {
  options.signIn.requireConfirmedEmail = false;
  options.password.requiredLength = 8;
});

// Connect to your database
AddTypeOrmDataSource(container, myDataSource);

// Use the UserManager
const userManager = container.get<UserManager<MyUser>>('UserManager');
const user = new MyUser();
user.email = "user@example.com";
const result = await userManager.CreateAsync(user, "password123");
```

## API Demo Endpoints

The demo application includes two main endpoints:

- `POST /register` - Register a new user
- `POST /login` - Authenticate a user

## Security Features

- Secure password hashing with bcrypt
- Protection against brute force attacks through lockout policies
- Email verification for account security
- Flexible password policies 