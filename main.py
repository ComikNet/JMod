import asyncio
import hashlib
import json
from re import S
import time
from abc import ABC, abstractmethod
from enum import Enum
from http.cookies import BaseCookie
from typing import Any
from venv import logger

import aiohttp
from common import multi_thread_launcher
from curl_cffi import requests as postman
from fastapi import HTTPException
from jmcomic import JmcomicText, JmCryptoTool, JmOption
from yarl import URL

from Models.comic import BaseComicInfo
from Models.plugins import BasePlugin, IAuth
from Models.response import StandardResponse
from Models.user import UserData


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
        read_timeout: int = 20,
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
    __src__ = "jm"

    def on_load(self) -> bool:
        _domain_set = set[str](
            [
                "https://www.cdn-eldenringproxy.xyz",
                "https://cn-appdata.jmapiproxy2.cc",
                "https://www.jmapinodeudzn.xyz",
                "https://www.jmapinode.xyz",
            ]
        )

        _domain_status = dict[str, tuple[bool, int]]()

        def _test_domain(url: str):

            time_start = time.time()
            try:

                async def _test():
                    req = JMRequests(url)
                    res = await req.get(
                        "/album", params={"comicName": "", "id": "123456"}
                    )
                    await req.close()
                    if res.status_code != 200:
                        raise Exception("Invalid response from server")
                    else:
                        _domain_status[url] = (
                            True,
                            int((time.time() - time_start) * 1000),
                        )

                asyncio.run(_test())

            except:
                _domain_status[url] = (False, -1)

        multi_thread_launcher(iter_objs=_domain_set, apply_each_obj_func=_test_domain)

        fastest = ("", (False, 99999))
        for domain, status in _domain_status.items():
            if status[0] and status[1] < fastest[1][1]:
                fastest = (domain, status)
        if not fastest[1][0]:
            logger.error("JMod failed to get a valid api source")
            return False

        logger.info(
            f"JMod will use {fastest[0]} as the api source, the latency is {fastest[1][1]}ms"
        )
        self.api_url = fastest[0]

        return True

    async def login(
        self, body: dict[str, str], user_data: UserData
    ) -> StandardResponse:
        req = JMRequests(self.api_url, user_data.get_src_cookies(self.__src__))
        res = await req.post("/login", body)
        user_data.set_src_cookies(self.__src__, req.filter_session_cookies("AVS"))
        await req.close()

        return res

    async def get_favor(
        self,
        user_data: UserData,
        data: dict[str, str] | None = None,
    ) -> StandardResponse:
        if data is None:
            data = dict()

        page = data.get("page", "1")
        sort_mode = FavorSortMode(data.get("sort", FavorSortMode.RecordTime))

        req = JMRequests(self.api_url, user_data.get_src_cookies(self.__src__))
        res = await req.get("/favorite", params={"page": page, "sort": sort_mode.value})
        await req.close()
        
        return res

    def search(self, keyword: str) -> list[BaseComicInfo]:
        return []
