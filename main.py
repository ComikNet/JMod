import hashlib
import json
import time
from abc import ABC, abstractmethod
from enum import Enum
from http.cookies import BaseCookie
from typing import Any

import aiohttp
from fastapi import HTTPException
from jmcomic import JmCryptoTool
from yarl import URL

from Models.comic import BaseComicInfo
from Models.plugins import BasePlugin, IAuth
from Models.response import StandardResponse
from Models.user import User, UserData
from Services.Modulator.manager import PluginUtils

# Temporary url config
api_url = "https://www.cdn-eldenringproxy.xyz"


class AsyncRequests(ABC):
    """
    AsyncRequests Class
    ~~~~~~~~~~~~~~~~~~~~~
    AsyncRequests is a packaged web requests class which based on aiohttp.
    """

    def __init__(
        self,
        base_url: str,
        cookies: BaseCookie[str] | None = None,
        conn_timeout: int = 15,
        read_timeout: int = 45,
    ) -> None:
        self.base_url = base_url
        self.session = aiohttp.ClientSession(
            base_url=base_url,
            conn_timeout=conn_timeout,
            cookie_jar=aiohttp.CookieJar(),
            read_timeout=read_timeout,
            connector=aiohttp.TCPConnector(verify_ssl=False, force_close=True),
        )

        if cookies is not None:
            self.set_session_cookies(cookies)

    async def close(self) -> None:
        await self.session.close()

    def set_session_cookies(self, cookies: BaseCookie[str]) -> None:
        self.session.cookie_jar.update_cookies(cookies, URL(self.base_url))

    def filter_session_cookies(self, *keys: str) -> BaseCookie[str]:
        cookies = self.session.cookie_jar.filter_cookies(URL(self.base_url))

        if keys:
            filtered_cookies = BaseCookie[str]()
            for key in keys:
                if key in cookies:
                    filtered_cookies[key] = cookies[key]
            return filtered_cookies
        else:
            return cookies

    def clear_session_cookies(self) -> None:
        self.session.cookie_jar.clear()

    @abstractmethod
    async def get(
        self, url: str, params: dict[str, str] | None = None
    ) -> StandardResponse:
        pass

    @abstractmethod
    async def post(
        self, url: str, data: dict[str, str] | None = None
    ) -> StandardResponse:
        pass


class JMRequests(AsyncRequests):
    def __init__(
        self,
        base_url: str,
        cookies: BaseCookie[str] | None = None,
        conn_timeout: int = 15,
        read_timeout: int = 45,
    ) -> None:
        super().__init__(base_url, cookies, conn_timeout, read_timeout)

    @staticmethod
    def dataDecrypt(req_time: int, data: str) -> dict[str, Any]:
        return json.loads(JmCryptoTool.decode_resp_data(data, req_time))

    async def get(
        self, url: str, params: dict[str, str] | None = None
    ) -> StandardResponse[dict[str, Any]]:
        req_time = int(time.time())
        headers = JMHeaders(req_time, "GET").headers

        try:
            async with self.session.get(
                url, headers=headers, params=params
            ) as response:
                try:
                    res = json.loads(await response.read())
                except json.JSONDecodeError:
                    raise HTTPException(502, "Upstream server responded incorrectly")
        except Exception as e:
            raise HTTPException(500, e.__str__())

        try:
            if res["code"] == 200:
                return StandardResponse[dict[str, Any]](
                    response.status,
                    data=self.dataDecrypt(req_time, res["data"]),
                )
            else:
                return StandardResponse(response.status, message=res["errorMsg"])
        except:
            raise HTTPException(502, "Unable to decode upstream server response")

    async def getContent(
        self, url: str, params: dict[str, str] | None = None
    ) -> StandardResponse[bytes]:
        req_time = int(time.time())
        headers = JMHeaders(req_time, "GET", True).headers

        try:
            async with self.session.post(
                url, headers=headers, params=params
            ) as response:
                res = await response.read()

                if response.status == 200:
                    return StandardResponse[bytes](
                        status_code=response.status, data=res
                    )
                else:
                    raise HTTPException(502, "Upstream server responded incorrectly")
        except:
            raise HTTPException(500, "Unable to get response from upstream server")

    async def post(
        self, url: str, data: dict[str, str] | None = None
    ) -> StandardResponse[dict[str, Any]]:
        req_time = int(time.time())
        headers = JMHeaders(req_time, "POST").headers

        try:
            async with self.session.post(url, headers=headers, data=data) as response:
                try:
                    res = json.loads(await response.read())
                except json.JSONDecodeError:
                    raise HTTPException(502, "Upstream server responded incorrectly")
        except Exception as e:
            raise HTTPException(500, e.__str__())

        try:
            if res["code"] == 200:
                return StandardResponse[dict[str, Any]](
                    response.status,
                    data=self.dataDecrypt(req_time, res["data"]),
                )
            else:
                return StandardResponse(response.status, message=res["errorMsg"])
        except:
            raise HTTPException(502, "Unable to decode upstream server response")

    async def postContent(
        self, url: str, data: dict[str, str] | None = None
    ) -> StandardResponse[bytes]:
        req_time = int(time.time())
        headers = JMHeaders(req_time, "POST").headers

        try:
            async with self.session.post(url, headers=headers, data=data) as response:
                res = await response.read()

                if response.status == 200:
                    return StandardResponse[bytes](response.status, data=res)
                else:
                    raise HTTPException(502, "Upstream server responded incorrectly")
        except:
            raise HTTPException(500, "Unable to get response from upstream server")


class JMHeaders:
    headers = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip",
        "User-Agent": "Mozilla/5.0 (Linux; Android 7.1.2; DT1901A Build/N2G47O; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/86.0.4240.198 Mobile Safari/537.36",
        "Version": "v1.2.3",
    }

    def __init__(self, time: int, method: str, isContent: bool = False) -> None:
        if isContent:
            param = f"{time}18comicAPPContent"
        else:
            param = f"{time}18comicAPP"
        token = hashlib.md5(param.encode("utf-8")).hexdigest()

        self.headers["tokenparam"] = f"{time},1.7.0"
        self.headers["token"] = token

        if method == "POST":
            self.headers["Content-Type"] = "application/x-www-form-urlencoded"

        elif method == "TEST":
            self.headers["cache-control"] = "no-cache"
            self.headers["expires"] = "0"
            self.headers["pragma"] = "no-cache"
            self.headers["authorization"] = ""


class FavorSortMode(Enum):
    RecordTime = "mr"
    UpdateTime = "mp"


class JMod(BasePlugin, IAuth):
    def on_load(self) -> bool:
        print("Hello, world!")
        return True

    async def login(
        self, body: dict[str, str], user_data: UserData
    ) -> StandardResponse:
        req = JMRequests(api_url, user_data.get_src_cookies("jm"))
        res = await req.post("/login", body)
        user_data.plugin_cookies["jm"] = req.filter_session_cookies("AVS")
        await req.close()

        return res

    async def get_favor(
        self,
        user_data: UserData,
        data: dict[str, str] | None = None,
    ) -> StandardResponse:
        if data is None:
            page = "1"
            sort_mode = FavorSortMode.RecordTime
        else:
            page = data.get("page", "1")
            sort_mode = FavorSortMode(data.get("sort", FavorSortMode.RecordTime))

        req = JMRequests(api_url, user_data.get_src_cookies("jm"))
        res = await req.get("/favorite", params={"page": page, "sort": sort_mode.value})
        await req.close()

        return res

    def search(self, keyword: str) -> list[BaseComicInfo]:
        return []
