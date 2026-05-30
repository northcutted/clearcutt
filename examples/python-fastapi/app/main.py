from fastapi import FastAPI

app = FastAPI(title="ClearCutt Python 3.14 Hardened Service")

@app.get("/")
def read_root():
    return {"message": "Hello from ClearCutt Python 3.14 Hardened Service!"}

@app.get("/healthz")
def healthcheck():
    return {"status": "healthy"}
