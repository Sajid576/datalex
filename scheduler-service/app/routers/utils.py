from typing import Annotated
import traceback
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from pydantic import BaseModel, EmailStr

from ..dependencies import get_gmail_service
from ..services.gmail import GmailService
from ..services.google_drive import ChunkFileService, GoogleDriveService
from ..utils.env import get_env_variable
from settings import TARGET_GOOGLE_DRIVE_PATH,SURICATA_LOG_TARGET_PATH

router = APIRouter(tags=["utils"])


class EmailRequest(BaseModel):
    """
    Email request model.
    """

    email: EmailStr
    subject: str
    message: str


def send_email_background(
    gmail_service: GmailService, email: EmailStr, subject: str, message: str
):
    """
    Background task to send an email using GmailService.

    Parameters:
        gmail_service (GmailService): Instance of the GmailService.
        email (EmailStr): Email address to send the email to.
        subject (str): Subject of the email.
        message (str): Body of the email.

    Raises:
        HTTPException: If an error occurs during email composition or sending.
    """

    try:
        message = gmail_service.compose_email(email, subject, message)
        gmail_service.send_email(message)
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"An error occurred: {error}")


@router.post("/send-email", status_code=status.HTTP_201_CREATED)
def send_email(
    email_data: EmailRequest,
    gmail_service: Annotated[GmailService, Depends(get_gmail_service)],
    background_tasks: BackgroundTasks,
) -> dict:
    """
    Send an email using the Gmail API.
    """

    background_tasks.add_task(
        send_email_background,
        gmail_service,
        email_data.email,
        email_data.subject,
        email_data.message,
    )
    print("Email sending process scheduled in the background.")

    return {"status": "Success", "message": "Email scheduled for delivery"}


@router.post("/transfer-logs", status_code=status.HTTP_201_CREATED)
def transfer_suricata_logs(
) -> dict:
    print('=================SURICATA LOG TRANSFER INITIATING===========')
    suricata_json_path = get_env_variable('SURICATA_LOG_PATH')
    
    try:
        # drive_link = GoogleDriveService().upload_file(suricata_json_path, TARGET_GOOGLE_DRIVE_PATH)
        ChunkFileService().clone_json_file_to_list(suricata_json_path,SURICATA_LOG_TARGET_PATH)
        print('=================SURICATA LOG TRANSFER FINISHED===========')
        return {
            "success": True,
            "message":"Upload Success"
        }
    except Exception as error:
        print('=================LOG TRANSFER FAILED===========')
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"An error occurred: {error}")
