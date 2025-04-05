from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import RedirectResponse

from .routers import utils
from .cron_jobs.transfer_logs import init_cron_jobs


description = "This app is a scheduler service for SIEM, which will fetch logs from SIEM and store them in the google drive for the GPT service to use. also this app has a email sending endpoint that will be triggered by the RAG agent of GPT service."

app = FastAPI(
    title="SIEM Scheduler Service",
    description=description,
    version="1.0.0",
)

# Initialize cron jobs after FastAPI app creation
init_cron_jobs()

app.include_router(utils.router)

security = HTTPBasic()

def get_current_username(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = "admin"
    correct_password = "123456"
    if credentials.username != correct_username or credentials.password != correct_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

@app.get("/docs", include_in_schema=False)
async def get_swagger_ui_html(credentials: HTTPBasicCredentials = Depends(get_current_username)):
    return RedirectResponse(url="/docs")

# Custom OpenAPI configuration
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="SIEM Scheduler Service",
        version="1.0.0",
        description=description,
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

@app.get("/")
async def health_check() -> str:
    return "OK"
