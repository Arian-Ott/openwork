# Workday Tracker

>[!CAUTION]
>This repo is work in progress and not yet stable.

## Overview

The Workday Tracker API is built using FastAPI and provides endpoints for user authentication and worklog management.

## Endpoints

### Authentication

- **POST /auth/token**: Obtain an access token by providing a username and password.
- **POST /auth/register**: Register a new user.
- **GET /auth/protected**: Access a protected route using a valid token.
- **POST /auth/refresh**: Refresh the access token.
- **POST /auth/change_password**: Change the user's password.
- **GET /auth/me**: Retrieve the current user's details.

### Worklog

- **POST /worklog/pause**: Pause the worklog.

## Setup

1. Clone the repository.
2. Create a virtual environment and activate it.
3. Install the dependencies:
    ```sh
    pip install -r requirements.txt
    ```
4. Create a `.env` file with the following variables:
    ```env
    SECRET_KEY=your_secret_key
    DB_USER=your_db_user
    DB_PASSWORD=your_db_password
    DB_HOST=your_db_host
    DEBUG=True
    ```

## Running the Application

1. Start the FastAPI server:
    ```sh
    uvicorn main:app --reload
    ```

2. The API will be available at `http://localhost:8000`.

## Testing the Endpoints

You can use tools like Postman or curl to test the endpoints. For example, to obtain an access token:

```sh
curl -X POST "http://localhost:8000/auth/token" -d "username=your_username&password=your_password"