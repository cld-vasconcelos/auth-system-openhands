# Authentication System API

## Overview
This Django-based authentication and user management system provides a robust and secure API for handling user authentication, authorization, and account management. The system is designed with security and scalability in mind, offering features like JWT authentication, OAuth integration, and Multi-Factor Authentication (MFA).

### Key Features
- User registration and management
- JWT-based authentication
- OAuth2 integration for social logins
- Multi-Factor Authentication (MFA) support
- Password reset and email verification
- Role-based access control
- Rate limiting for enhanced security
- CSRF protection
- Secure password hashing with Argon2

## Tech Stack

### Backend
- Django - Web framework
- Django REST Framework (DRF) - API development
- Django Allauth - Authentication provider
- PostgreSQL - Database
- JWT - Token-based authentication

### Security
- Argon2 - Password hashing
- CSRF protection
- Rate limiting
- SSL/TLS support

### Development Tools
- Poetry - Dependency management
- Docker - Containerization
- Make - Build automation

## Setup Instructions

### Prerequisites
- Docker and Docker Compose
- Python 3.8 or higher (for local development)
- Poetry (for local development)
- PostgreSQL (for local development without Docker)

### Running with Docker

1. Clone the repository:
   ```sh
   git clone <repository-url>
   cd auth-system
   ```

2. Start the application using Docker Compose:
   ```sh
   docker-compose up -d
   ```

3. Create a superuser (admin account):
   ```sh
   make create-superuser
   ```

4. Access the application at http://localhost:8000

To stop the containers:
```sh
docker-compose down
```

### Running Locally Without Docker

1. Install dependencies using Poetry:
   ```sh
   poetry install --no-root
   ```

2. Activate the virtual environment:
   ```sh
   poetry shell
   ```

3. Set up the database:
   ```sh
   make migrations
   make migrate
   ```

4. Create a superuser:
   ```sh
   make create-superuser
   ```

5. Start the development server:
   ```sh
   make runserver
   ```

6. Access the application at http://localhost:8000

### Running Tests

To run the test suite:

```sh
# Using Make
make test

# Using Docker
docker-compose run --rm web python manage.py test

# Using Poetry
poetry run python manage.py test
```

## API Documentation

The API documentation is available through two interfaces:

### Swagger UI
- URL: `/api/docs/swagger/`
- Interactive documentation with try-it-out functionality
- Authentication:
  1. Obtain a JWT token through `/api/token/`
  2. Click the "Authorize" button in Swagger UI
  3. Enter the token in format: `Bearer <your-token>`

### ReDoc
- URL: `/api/docs/redoc/`
- Clean, responsive documentation interface
- Ideal for API reference and documentation sharing

## Admin Dashboard

The Django Admin interface provides a user-friendly way to manage the application:

1. Access the admin panel at `/admin/`
2. Log in using superuser credentials
3. Manage users, permissions, and other application data

To create a superuser account:
```sh
make create-superuser
```

## Environment Variables

Create a `.env` file in the project root with the following variables:

```env
DEBUG=True
SECRET_KEY=your-secret-key
DATABASE_URL=postgres://user:password@localhost:5432/dbname
ALLOWED_HOSTS=localhost,127.0.0.1
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
