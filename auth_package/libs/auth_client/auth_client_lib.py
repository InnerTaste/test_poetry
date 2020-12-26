import json
import os
import requests
from typing import Optional
import urllib
import uuid

from pydantic import BaseModel
import jwt

REDIRECT_PATH_NAME_ONLY = "auth_callback"
REDIRECT_PATH = f"/{REDIRECT_PATH_NAME_ONLY}"

SIGNOUT_REDIRECT_PATH_NAME_ONLY = "azure_post_signout"
SIGNOUT_REDIRECT_PATH = f"/{SIGNOUT_REDIRECT_PATH_NAME_ONLY}"


class UserService:
    def get_UMP_container_url(self):
        return f'http://{os.getenv("UMP_CONTAINER_HOSTNAME")}'

    def get_UMP_exposed_url(self):
        return f'http://{os.getenv("UMP_EXPOSED_HOSTNAME")}'

    def get_client_id(self):
        return os.getenv("AAD_CLIENT_ID")

    def get_client_secret(self):
        return os.getenv("AAD_CLIENT_SECRET")


class User(BaseModel):
    sub: str
    name: str


class AuthClient:
    def __init__(
        self,
        base_url: str = None,
    ):
        self.base_url = base_url
        self.user_service_obj = UserService()

    def _create_continue_url(self, redirect_path: str):
        continue_url = urllib.parse.quote(f"{self.base_url}{redirect_path}", safe="")
        return continue_url

    def get_signup_url(
        self,
        state: Optional[str] = str(uuid.uuid4()),
        redirect_path: Optional[str] = REDIRECT_PATH_NAME_ONLY,
        next_url: Optional[str] = None,
    ):
        next_url = urllib.parse.quote(next_url, safe="")
        continue_url = self._create_continue_url(redirect_path)
        redirect_url = f"{self.user_service_obj.get_UMP_exposed_url()}/signup?continue_url={continue_url}&next_url={next_url}&state={state}"
        return redirect_url

    def get_signup_signin_url(
        self,
        state: Optional[str] = str(uuid.uuid4()),
        redirect_path: Optional[str] = REDIRECT_PATH_NAME_ONLY,
        next_url: Optional[str] = None,
    ):
        next_url = urllib.parse.quote(next_url, safe="")
        continue_url = self._create_continue_url(redirect_path)
        redirect_url = f"{self.user_service_obj.get_UMP_exposed_url()}/signup_signin?continue_url={continue_url}&next_url={next_url}&state={state}"
        return redirect_url

    def get_profile_edit_url(
        self,
        state: Optional[str] = str(uuid.uuid4()),
        redirect_path: Optional[str] = REDIRECT_PATH_NAME_ONLY,
        next_url: Optional[str] = None,
    ):
        next_url = urllib.parse.quote(next_url, safe="")
        continue_url = self._create_continue_url(redirect_path)
        redirect_url = f"{self.user_service_obj.get_UMP_exposed_url()}/profile_edit?continue_url={continue_url}&next_url={next_url}&state={state}"
        return redirect_url

    def get_signout_url(
        self,
        redirect_path: Optional[str] = SIGNOUT_REDIRECT_PATH_NAME_ONLY,
    ):
        continue_url = self._create_continue_url(redirect_path)
        redirect_url = f"{self.user_service_obj.get_UMP_exposed_url()}/signout?continue_url={continue_url}&next_url={continue_url}"
        return redirect_url

    def get_user(self, token: str):
        get_user_url = f"{self.user_service_obj.get_UMP_container_url()}/user?origin={urllib.parse.quote(self.base_url)}"
        x = requests.get(get_user_url, headers={"authorization": f"bearer {token}"})
        return json.loads(x.content)

    def get_public_key(self, token: str):
        get_token_url = (
            f"{self.user_service_obj.get_UMP_container_url()}/key?token={token}"
        )
        x = requests.get(get_token_url)
        return x.text

    def get_user_and_verify_token(self, token: str, client_id: Optional[str] = None):
        # This step is commented until app_one/two have different domain name
        # conflict when setting cookie token under localhost (but diff port)
        # if client_id is None:
        #     client_id = self.user_service_obj.get_client_id()

        # Ths is alternative for localhost, get the unverified from then token instead
        client_id = jwt.decode(token, verify=False)["aud"]

        key = self.get_public_key(token)
        jwt_public_key = jwt.algorithms.RSAAlgorithm.from_jwk(
            json.dumps(json.loads(key))
        )
        payload = jwt.decode(
            token,
            key=jwt_public_key,
            algorithms=["RS256"],
            audience=client_id,
        )
        sub: str = payload.get("sub")
        name: str = payload.get("name")
        if sub is None:
            return None
        else:
            user_data = User(sub=sub, name=name)
            return user_data
