import os
import base64
from email.message import EmailMessage

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from pydantic import EmailStr
from google.auth.exceptions import RefreshError

from settings import CREDENTIALS_PATH, TOKEN_PATH

# Declare the scopes of Gmail API
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]


def get_credentials():
    """
    Get Gmail API credentials.

    Returns:
        creds: Gmail API credentials.
    """

    creds = None

    # Try to load existing token
    if os.path.exists(TOKEN_PATH):
        try:
            creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
        except Exception:
            # If token file is corrupted, remove it
            os.remove(TOKEN_PATH)
            creds = None

    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        try:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    CREDENTIALS_PATH, SCOPES
                )
                creds = flow.run_local_server(port=0)

            # Save the credentials for the next run
            with open(TOKEN_PATH, "w") as token:
                token.write(creds.to_json())
        except RefreshError:
            # If refresh fails, force new authentication
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_PATH, SCOPES
            )
            creds = flow.run_local_server(port=0)
            with open(TOKEN_PATH, "w") as token:
                token.write(creds.to_json())

    return creds


class GmailService:
    """
    Service class for interacting with Gmail API.

    Attributes:
        creds: Gmail API credentials.
    """

    def __init__(self):
        self.creds = get_credentials()

    def compose_email(self, recipient: EmailStr, subject: str, body: str) -> dict:
        """
        Compose an email message.

        Parameters:
            recipient (EmailStr): Email address of the recipient.
            subject (str): Subject of the email.
            body (str): Body content of the email.

        Returns:
            dict: Composed email message.
        """

        message = EmailMessage()

        message.set_content(body)

        message["To"] = recipient
        message["Subject"] = subject

        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

        created_message = {"raw": encoded_message}

        return created_message

    def send_email(self, message: dict):
        """
        Send an email using Gmail API.

        Parameters:
            message (dict): Composed email message.
        """

        try:
            service = build("gmail", "v1", credentials=self.creds)

            send_message = (
                service.users()
                .messages()
                .send(userId="me", body=message)
                .execute()
            )
            print(f'Message Id: {send_message["id"]}')
        except HttpError as error:
            print(f"An error occurred: {error}")
            send_message = None
        return send_message
