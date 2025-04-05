from .services.gmail import GmailService


def get_gmail_service() -> GmailService:
    """
    Function to get an instance of the GmailService.

    Returns:
        GmailService: Instance of the GmailService.
    """

    return GmailService()
