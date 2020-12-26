import json
import requests
from typing import Optional
import urllib
import uuid

from fastapi import APIRouter
from fastapi import Request
from fastapi import Depends
from fastapi import HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import jwt
from starlette import status
from starlette.responses import RedirectResponse
from starlette.responses import Response

from libs.auth_client.auth_client_lib import AuthClient
from libs.auth_client.auth_client_lib import REDIRECT_PATH
from libs.auth_client.auth_client_lib import SIGNOUT_REDIRECT_PATH
from libs.auth_client.auth_client_lib import User
from libs.auth_client.model.session import OAuth2PasswordBearerCookie


router = APIRouter()
router.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
oauth2_scheme = OAuth2PasswordBearerCookie(tokenUrl="/token")

COOKIE_AUTHORIZATION_NAME = "Authorization"
COOKIE_DOMAIN = "localhost"


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        auth = AuthClient()
        user = auth.get_user_and_verify_token(token=token)
        if user is None:
            raise credentials_exception
        return user
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate credentials {type(err).__name__}",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.get("/user_session")
def get_user_session(request: Request, current_user: User = Depends(get_current_user)):
    return {"user_session": current_user, "Back to Index": str(request.base_url)}


@router.get("/signup")
async def signup(request: Request):
    auth = AuthClient(str(request.base_url))
    auth_action_url = auth.get_signup_url(
        state=str(uuid.uuid4()), next_url=request.headers["referer"]
    )
    response = RedirectResponse(url=auth_action_url)

    return response


@router.get("/signup_signin")
async def signup_signin(request: Request):
    auth = AuthClient(str(request.base_url))
    auth_action_url = auth.get_signup_signin_url(
        state=str(uuid.uuid4()), next_url=request.headers["referer"]
    )
    response = RedirectResponse(url=auth_action_url)

    return response


# Redirect from UMP Library Service.
@router.get(REDIRECT_PATH)
async def redirect_callback(
    request: Request, response: Response, token: str, next_url: str
):
    response = RedirectResponse(url=next_url)
    response.set_cookie(
        key=COOKIE_AUTHORIZATION_NAME,
        value=f"Bearer {token}",
        domain=COOKIE_DOMAIN,
        httponly=True,
        max_age=1800,
        expires=1800,
    )
    return response


@router.get("/signout")
async def signout(request: Request):
    auth = AuthClient(str(request.base_url))
    auth_action_url = auth.get_signout_url()
    response = RedirectResponse(url=auth_action_url)

    return response


# Redirect from UMP Library Service post-signout.
@router.get(SIGNOUT_REDIRECT_PATH)
async def signout_redirect_callback(request: Request, response: Response):
    response = RedirectResponse(url="/")
    response.delete_cookie(
        key=COOKIE_AUTHORIZATION_NAME,
        path="/",
        domain=COOKIE_DOMAIN,
    )

    return response


@router.get("/user")
def user(
    request: Request,
    current_user: User = Depends(get_current_user),
    token: str = Depends(oauth2_scheme),
):
    auth = AuthClient(str(request.base_url))
    user_profile = auth.get_user(token)

    return user_profile


@router.get("/user/edit")
def user_edit_profile(
    request: Request,
):
    auth = AuthClient(str(request.base_url))
    auth_action_url = auth.get_profile_edit_url(
        state=str(uuid.uuid4()), next_url=request.headers["referer"]
    )
    response = RedirectResponse(url=auth_action_url)

    return response
