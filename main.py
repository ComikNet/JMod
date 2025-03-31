import asyncio
import hashlib
import json
import logging
import time
from abc import ABC, abstractmethod
from enum import Enum
from http.cookiejar import CookieJar
from typing import Any, override

import httpx
from fastapi import HTTPException
from jmcomic import JmCryptoTool
from pydantic import BaseModel

from Models.comic import BaseComicInfo, ComicInfo
from Models.plugins import BasePlugin, IAuth
from Models.response import StandardResponse
from Models.user import UserData

logger = logging.getLogger("[JMod]")


class JMApiData(BaseModel):
    web_urls: list[str]
    api_urls: list[str]
    proxy_api_url: str
    cdn_api_url: str
    header_version: str


def parse_api_data(data_str: str) -> JMApiData:
    data = {}
    for line in data_str.strip().split("\n"):
        k, v = line.split("=", 1)
        if "," in v:
            v = v.split(",")
        data[k] = v

    return JMApiData(
        web_urls=data["UrlList"],
        api_urls=data["Url2List"],
        proxy_api_url=data["ProxyApiUrl"],
        cdn_api_url=data["CdnApiUrl"],
        header_version=data["HeaderVer"],
    )


def update_jm_apis() -> JMApiData:
    resp = httpx.get("https://app.ggo.icu/JMComic/config.txt")
    if resp.status_code != 200:
        raise HTTPException(502, "Unable to get API data from upstream server")
    data = resp.text
    return parse_api_data(data)


class AsyncRequests(ABC):
    """
    AsyncRequests Class
    ~~~~~~~~~~~~~~~~~~~~~
    AsyncRequests is a packaged web requests class which based on aiohttp.
    """

    def __init__(
        self,
        base_url: str,
        base_timeout: int,
        conn_timeout: int,
        read_timeout: int,
        cookies: CookieJar | dict[str, str] | None = None,
    ) -> None:
        self.base_url = base_url
        self.session = httpx.AsyncClient(
            base_url=base_url,
            timeout=httpx.Timeout(
                timeout=base_timeout,
                connect=conn_timeout,
                read=read_timeout,
            ),
            cookies=cookies,
        )

    async def close(self) -> None:
        await self.session.aclose()

    def add_session_cookies(self, cookies: CookieJar | dict[str, str]) -> None:
        self.session.cookies.update(cookies)

    def clear_session_cookies(self) -> None:
        self.session.cookies.clear()

    def export_session_cookies(self, *key: str) -> dict[str, str | None]:
        if not key:
            return {cookie.name: cookie.value for cookie in self.session.cookies.jar}

        return {
            cookie.name: cookie.value
            for cookie in self.session.cookies.jar
            if cookie.name in key
        }

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
        version: str,
        cookies: CookieJar | dict[str, str] | None = None,
        base_timeout: int = 15,
        conn_timeout: int = 20,
        read_timeout: int = 25,
    ) -> None:
        super().__init__(base_url, base_timeout, conn_timeout, read_timeout, cookies)
        self.version = version

    @staticmethod
    def dataDecrypt(req_time: int, data: str) -> dict[str, Any]:
        return json.loads(JmCryptoTool.decode_resp_data(data, req_time))

    async def get(
        self, url: str, params: dict[str, str] | None = None
    ) -> StandardResponse[dict[str, Any]]:
        req_time = int(time.time())
        headers = JMHeaders(self.version, req_time, "GET").headers

        try:
            response = await self.session.get(url, headers=headers, params=params)
            try:
                res = response.json()
            except json.JSONDecodeError:
                raise HTTPException(502, "Upstream server responded incorrectly")
        except Exception:
            raise HTTPException(500, "Unable to get response from upstream server")

        try:
            if res["code"] == 200:
                return StandardResponse[dict[str, Any]](
                    response.status_code,
                    data=JMRequests.dataDecrypt(req_time, data=res["data"]),
                )
            else:
                return StandardResponse(response.status_code, message=res["errorMsg"])
        except Exception:
            raise HTTPException(502, "Unable to decode upstream server response")

    async def getContent(
        self, url: str, params: dict[str, str] | None = None
    ) -> StandardResponse[bytes]:
        req_time = int(time.time())
        headers = JMHeaders(self.version, req_time, "GET", True).headers

        try:
            response = await self.session.post(url, headers=headers, params=params)
            res = response.read()

            if response.status_code == 200:
                return StandardResponse[bytes](
                    status_code=response.status_code, data=res
                )
            else:
                raise HTTPException(502, "Upstream server responded incorrectly")
        except Exception:
            raise HTTPException(500, "Unable to get response from upstream server")

    async def post(
        self, url: str, data: dict[str, str] | None = None
    ) -> StandardResponse[dict[str, Any]]:
        req_time = int(time.time())
        headers = JMHeaders(self.version, req_time, "POST").headers

        try:
            response = await self.session.post(url, headers=headers, data=data)
            try:
                res = response.json()
            except json.JSONDecodeError:
                raise HTTPException(502, "Upstream server responded incorrectly")
        except Exception:
            raise HTTPException(500, "Unable to get response from upstream server")

        try:
            if res["code"] == 200:
                return StandardResponse[dict[str, Any]](
                    response.status_code,
                    data=self.dataDecrypt(req_time, res["data"]),
                )
            else:
                return StandardResponse(response.status_code, message=res["errorMsg"])
        except Exception:
            raise HTTPException(502, "Unable to decode upstream server response")

    async def postContent(
        self, url: str, data: dict[str, str] | None = None
    ) -> StandardResponse[bytes]:
        req_time = int(time.time())
        headers = JMHeaders(self.version, req_time, "POST").headers

        try:
            response = await self.session.post(url, headers=headers, data=data)
            res = response.read()

            if response.status_code == 200:
                return StandardResponse[bytes](response.status_code, data=res)
            else:
                raise HTTPException(502, "Upstream server responded incorrectly")
        except Exception:
            raise HTTPException(500, "Unable to get response from upstream server")


class JMHeaders:
    headers = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip",
        "User-Agent": "Mozilla/5.0 (Linux; Android 7.1.2; DT1901A Build/N2G47O; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/86.0.4240.198 Mobile Safari/537.36",
    }

    def __init__(
        self, version: str, time: int, method: str, isContent: bool = False
    ) -> None:
        if isContent:
            param = f"{time}18comicAPPContent"
        else:
            param = f"{time}18comicAPP"
        token = hashlib.md5(param.encode("utf-8")).hexdigest()

        self.headers["tokenparam"] = f"{time},1.7.0"
        self.headers["token"] = token
        self.headers["Version"] = version

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

    @override
    def on_unload(self) -> None:
        logger.info("Plugin unloaded, goodbye!")

    @override
    def on_load(self) -> bool:
        logger.info("Initializing...")
        if not asyncio.run(self.init_api()):
            logger.error("Failed to initialize API")
            return False
        logger.info("API initialized successfully")

        return True

    async def init_api(self) -> bool:
        _api_data = update_jm_apis()
        _api_data.api_urls.append(_api_data.proxy_api_url)
        _api_data.api_urls.append(_api_data.cdn_api_url)
        self._version = _api_data.header_version

        _domain_status = dict[str, tuple[bool, int]]()

        async def _test_domain(url: str) -> None:
            time_start = time.time()
            try:
                req = JMRequests(url, self._version)
                res = await req.get("/album", params={"comicName": "", "id": "123456"})
                await req.close()

                if res.status_code != 200:
                    raise Exception("Invalid response from server")

                _domain_status[url] = (True, int((time.time() - time_start) * 1000))
            except Exception as e:
                logger.exception(f"Failed to connect to {url}: {e}")
                _domain_status[url] = (False, -1)

        task = [_test_domain(url) for url in _api_data.api_urls]
        await asyncio.gather(*task)

        fastest = ("", (False, 99999))
        for domain, status in _domain_status.items():
            logger.debug(f"{domain} status: {status}")
            if status[0] and status[1] < fastest[1][1]:
                fastest = (domain, status)
        if not fastest[1][0]:
            logger.error("Failed to get any valid api source")
            return False

        logger.info(
            f"Using {fastest[0]} as the api source, the latency is {fastest[1][1]}ms"
        )
        self.api_url = fastest[0]

        return True

    async def login(
        self, body: dict[str, str], user_data: UserData
    ) -> StandardResponse:
        req = JMRequests(
            self.api_url, self._version, cookies=user_data.get_src_cookies(self.__src__)
        )
        res = await req.post("/login", body)
        await req.close()
        user_data.set_src_cookies(self.__src__, req.export_session_cookies("AVS"))
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

        req = JMRequests(
            self.api_url, self._version, cookies=user_data.get_src_cookies(self.__src__)
        )
        res = await req.get("/favorite", params={"page": page, "sort": sort_mode.value})
        await req.close()

        return res

    def search(self, keyword: str) -> list[BaseComicInfo]:
        return []

    def album(self, album_id: str) -> ComicInfo:
        return ComicInfo()
