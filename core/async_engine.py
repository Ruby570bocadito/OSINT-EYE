"""OSINT EYE - Async Core Engine"""

import asyncio
import aiohttp
import ssl
import time
import random
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class AsyncConfig:
    """Async engine configuration"""

    max_concurrent: int = 50
    timeout: int = 10
    rate_limit: float = 0.0
    retries: int = 2
    stealth: bool = False
    paranoid: bool = False
    proxy: str = None
    tor: bool = False

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
        "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
    ]

    def get_ua(self) -> str:
        return random.choice(self.USER_AGENTS)

    def get_delay(self) -> float:
        if self.paranoid:
            return random.uniform(30, 120)
        elif self.stealth:
            return random.uniform(2, 8)
        elif self.rate_limit > 0:
            return self.rate_limit
        return random.uniform(0.1, 0.5)


class AsyncSession:
    """Async HTTP session with rate limiting and retries"""

    def __init__(self, config: AsyncConfig = None):
        self.config = config or AsyncConfig()
        self._session = None
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent)
        self._last_request = 0
        self.stats = {"requests": 0, "errors": 0, "retries": 0}

    async def __aenter__(self):
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(
            ssl=ssl_ctx,
            limit=self.config.max_concurrent,
            ttl_dns_cache=300,
        )

        timeout = aiohttp.ClientTimeout(total=self.config.timeout)

        session_kwargs = {
            "connector": connector,
            "timeout": timeout,
            "headers": {"User-Agent": self.config.get_ua()},
        }

        if self.config.proxy:
            session_kwargs["proxy"] = self.config.proxy

        self._session = aiohttp.ClientSession(**session_kwargs)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()

    async def _apply_rate_limit(self):
        delay = self.config.get_delay()
        elapsed = time.time() - self._last_request
        if elapsed < delay:
            await asyncio.sleep(delay - elapsed)
        self._last_request = time.time()

    async def get(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        async with self._semaphore:
            await self._apply_rate_limit()

            for attempt in range(self.config.retries + 1):
                try:
                    self.stats["requests"] += 1
                    headers = {"User-Agent": self.config.get_ua()}
                    if "headers" in kwargs:
                        headers.update(kwargs.pop("headers"))

                    resp = await self._session.get(url, headers=headers, **kwargs)
                    return resp
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    self.stats["errors"] += 1
                    if attempt < self.config.retries:
                        self.stats["retries"] += 1
                        await asyncio.sleep(2**attempt)
                    else:
                        return None

    async def post(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        async with self._semaphore:
            await self._apply_rate_limit()

            for attempt in range(self.config.retries + 1):
                try:
                    self.stats["requests"] += 1
                    headers = {"User-Agent": self.config.get_ua()}
                    if "headers" in kwargs:
                        headers.update(kwargs.pop("headers"))

                    resp = await self._session.post(url, headers=headers, **kwargs)
                    return resp
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    self.stats["errors"] += 1
                    if attempt < self.config.retries:
                        self.stats["retries"] += 1
                        await asyncio.sleep(2**attempt)
                    else:
                        return None

    async def get_text(self, url: str, **kwargs) -> Optional[str]:
        resp = await self.get(url, **kwargs)
        if resp:
            try:
                return await resp.text()
            except Exception:
                return None
        return None

    async def get_json(self, url: str, **kwargs) -> Optional[Dict]:
        resp = await self.get(url, **kwargs)
        if resp:
            try:
                return await resp.json()
            except Exception:
                return None
        return None


class AsyncTaskRunner:
    """Run async tasks with progress tracking"""

    def __init__(self, config: AsyncConfig = None):
        self.config = config or AsyncConfig()
        self.results = []
        self.errors = []
        self.progress_callback = None

    async def run_batch(self, func: Callable, items: List, *args, **kwargs) -> List:
        """Run function on all items concurrently"""
        self.results = []
        self.errors = []

        semaphore = asyncio.Semaphore(self.config.max_concurrent)

        async def _run(item):
            async with semaphore:
                try:
                    result = await func(item, *args, **kwargs)
                    if result:
                        self.results.append(result)
                    return result
                except Exception as e:
                    self.errors.append({"item": item, "error": str(e)})
                    return None

        tasks = [_run(item) for item in items]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self.results

    async def run_batch_with_progress(
        self, func: Callable, items: List, progress_cb: Callable = None, *args, **kwargs
    ) -> List:
        """Run function with progress callback"""
        self.results = []
        self.errors = []
        completed = 0
        total = len(items)

        semaphore = asyncio.Semaphore(self.config.max_concurrent)

        async def _run(item):
            nonlocal completed
            async with semaphore:
                try:
                    result = await func(item, *args, **kwargs)
                    if result:
                        self.results.append(result)
                    completed += 1
                    if progress_cb:
                        progress_cb(completed, total)
                    return result
                except Exception as e:
                    self.errors.append({"item": item, "error": str(e)})
                    completed += 1
                    if progress_cb:
                        progress_cb(completed, total)
                    return None

        tasks = [_run(item) for item in items]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self.results


async def async_get_many(urls: List[str], config: AsyncConfig = None) -> Dict[str, Any]:
    """Fetch multiple URLs concurrently"""
    config = config or AsyncConfig()
    results = {}

    async with AsyncSession(config) as session:

        async def fetch(url):
            text = await session.get_text(url)
            return url, text

        tasks = [fetch(url) for url in urls]
        done = await asyncio.gather(*tasks, return_exceptions=True)

        for result in done:
            if isinstance(result, tuple) and len(result) == 2:
                results[result[0]] = {"content": result[1], "success": True}
            else:
                results[result[0] if isinstance(result, Exception) else str(result)] = {
                    "content": None,
                    "success": False,
                }

    return results


if __name__ == "__main__":

    async def main():
        config = AsyncConfig(max_concurrent=20, stealth=True)

        async with AsyncSession(config) as session:
            print("[*] Testing async session...")
            text = await session.get_text("https://example.com")
            if text:
                print(f"[+] Got {len(text)} chars")
            print(f"[*] Stats: {session.stats}")

        print("\n[*] Testing batch fetch...")
        urls = ["https://example.com", "https://httpbin.org/get"]
        results = await async_get_many(urls, config)
        for url, data in results.items():
            status = "OK" if data["success"] else "FAIL"
            print(f"  [{status}] {url}")

    asyncio.run(main())
