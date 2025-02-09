import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi_jwt_auth.exceptions import AuthJWTException
from routers import auth, password, policy, accounts

app = FastAPI()
app.include_router(policy.router)
app.include_router(password.router)
app.include_router(auth.router)
app.include_router(accounts.router)


@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(
        status_code=exc.status_code,  # type: ignore
        content={"detail": exc.message},  # type: ignore
    )


if __name__ == "__main__":
    uvicorn.run("main:app", reload=True)
