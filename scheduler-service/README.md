# Scheduler Service

A FastAPI-based scheduler service for SIEM, which fetches logs from SIEM and stores them in Google Drive for the GPT service. Includes an email sending endpoint triggered by the RAG agent of GPT service.

## Table of Contents

- [Scheduler Service](#scheduler-service)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
    - [Setup .env File](#setup-env-file)
    - [Run Locally with venv](#run-locally-with-venv)
  - [Usage](#usage)
  - [API Documentation](#api-documentation)
    - [Available Endpoints](#available-endpoints)
      - [Send Email](#send-email)
  - [Configuration](#configuration)
    - [Gmail API Setup](#gmail-api-setup)
  - [Project Structure](#project-structure)

## Installation


### Setup .env File

Create a `.env` file in the project root and add the following configurations:

```bash
HOST=127.0.0.1
PORT=8000
IS_DEV=true

# Gmail API
CREDENTIALS_PATH=app/configs/credentials.json
TOKEN_PATH=app/configs/token.json
```

### Run Locally with venv

1. Create a virtual environment:
    ```bash
    python -m venv venv
    ```
2. Activate the virtual environment:
    - On Windows:
        ```bash
        .\venv\Scripts\activate
        ```
    - On Unix or macOS:
        ```bash
        source venv/bin/activate
        ```
3. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
4. Run the FastAPI app:
    ```bash
    python app.py
    ```

## Usage

Access the app at [http://localhost:8000](http://localhost:8000).

## API Documentation

Access API documentation:

- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

### Available Endpoints

#### Send Email
```http
POST /send-email
```

Request body:
```json
{
    "email": "recipient@example.com",
    "subject": "Email Subject",
    "message": "Email content goes here"
}
```

## Configuration

### Gmail API Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. [Create a Google Cloud project](https://developers.google.com/workspace/guides/create-project)
3. [Enable the Gmail API](https://developers.google.com/gmail/api/quickstart/python#enable_the_api)
3. [Configure the OAuth consent screen](https://developers.google.com/gmail/api/quickstart/python#configure_the_oauth_consent_screen)
4. [Authorize credentials for a desktop application](https://developers.google.com/gmail/api/quickstart/python#authorize_credentials_for_a_desktop_application)
6. Download the credentials and save as `credentials.json` in the project root
7. On first run:
   - The application will open a browser window
   - Log in with your Google account
   - Grant the necessary permissions
   - A token will be saved locally as `token.json`

## Project Structure
```
scheduler-service/
├── app/
│   ├── main.py          # FastAPI application
│   ├── routers/         # API routes
│   └── services/        # Service layer (Gmail, etc.)
├── app.py              # Application entry point
└── settings.py         # Configuration settings
```