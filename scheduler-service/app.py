import uvicorn
from settings import HOST, PORT, IS_DEV

if __name__ == "__main__":
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=IS_DEV)
