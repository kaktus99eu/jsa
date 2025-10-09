import asyncio
import argparse  
import aiohttp
import redis.asyncio as redis
from tqdm import tqdm
import jsbeautifier
import os
import tempfile
import re
from collections import defaultdict
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning, MarkupResemblesLocatorWarning
import random
import warnings
import time
import json
import subprocess
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import math
import sys
from playwright.async_api import async_playwright
import difflib

# [FIX] Подавляем все предупреждения, которые ломают вывод tqdm
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')

# ---------------- Config ----------------
SEEN_ENDPOINTS_KEY_TPL = "js_endpoints:{host}"
CONTENT_HASH_KEY_TPL = "content_hashes:{hash}"
CHECKPOINT_KEY_TPL = "checkpoint:{cycle_id}"
DEFAULT_BATCH_SIZE = 1500  # Batch size for checkpoint processing
DEFAULT_RETRY_ATTEMPTS = 2
DEFAULT_RETRY_DELAY = 5
CONCURRENT_REQUESTS = 5
LARGE_FILE_THRESHOLD = 2_000_000  # 2MB threshold for large files
LARGE_FILE_TIMEOUT = 90  # 90 seconds for large files
NORMAL_TIMEOUT = 30  # 30 seconds for normal files
AI_API_URL="http://localhost:8080"
AI_API_KEY="GPn4OnHcjdDRPVEu00HHBoRyU1PYN/3kgilKszC9fvs="

SCRIPT_BLOCKLIST_DOMAINS = {
    "google-analytics.com", "googletagmanager.com", "connect.facebook.net",
    "googleads.g.doubleclick.net", "cdn.optimizely.com", "cdn.segment.com",
    "adservice.google.com", "mc.yandex.ru", "vk.com",
    "adroll.com", "criteo.com", "twitter.com", "pinterest.com",
    "scorecardresearch.com", "adobedtm.com", "demdex.net"
}


def get_canonical_url(url: str) -> str:
    """
    Превращает URL вида '.../main.2a8f9b.js' в '.../main.js'.
    Решает проблему хаоса версионирования.
    """
    try:
        parsed_url = urlparse(url)
        path = parsed_url.path
        clean_path = path.split('?')[0].split('#')[0]
        # Regex для удаления типичных хэшей сборки (8+ hex символов, точки, дефисы)
        path_without_hash = re.sub(r'[\.-]([a-f0-9]{8,}|[A-Z0-9]{8,})', '', clean_path)
        canonical_url = parsed_url._replace(path=path_without_hash, query='', fragment='').geturl()
        return canonical_url
    except Exception:
        return url # В случае ошибки возвращаем оригинальный url

def create_beautified_diff(old_code: str, new_code: str, filename: str) -> str:
    """Создает diff между двумя отформатированными версиями кода."""
    opts = jsbeautifier.default_options()
    opts.indent_size = 2
    try: beautified_old = jsbeautifier.beautify(old_code, opts)
    except: beautified_old = old_code
    try: beautified_new = jsbeautifier.beautify(new_code, opts)
    except: beautified_new = new_code
    diff_lines = difflib.unified_diff(
        beautified_old.splitlines(keepends=True),
        beautified_new.splitlines(keepends=True),
        fromfile=f'a/{filename}',
        tofile=f'b/{filename}',
    )
    return ''.join(diff_lines)

async def send_diff_to_ai(session, diff, file_path, args):
    """Отправляет diff на анализ в server.py."""
    headers = {'Authorization': f'Bearer {AI_SERVER_API_KEY}', 'Content-Type': 'application/json'}
    payload = {'diff': diff, 'file_path': file_path}
    try:
        async with session.post(AI_SERVER_URL, json=payload, timeout=300) as resp:
            if resp.status == 200:
                return await resp.json()
            else:
                error_text = await resp.text()
                print(f"[!] AI_ERROR: Failed to analyze {file_path}. Status: {resp.status}, Body: {error_text[:200]}", file=sys.stderr)
                return None
    except Exception as e:
        print(f"[!] AI_ERROR: Request failed for {file_path}: {type(e).__name__}", file=sys.stderr)
        return None

REALISTIC_USER_AGENTS = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    # Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Safari macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    # Firefox macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

# --- ENHANCED REGEX PATTERNS FOR MODERN WEB APPS ---

# === ЧЕЛОВЕКОПОДОБНЫЕ ЗАДЕРЖКИ ===
class HumanLikeTiming:
    def __init__(self):
        self.last_request_time = 0
        self.session_start = time.time()
        self.request_count = 0
    
    async def get_delay(self) -> float:
        """Возвращает человекоподобную задержку"""
        self.request_count += 1
        current_time = time.time()
        base_delay = random.uniform(0.5, 1.0)
        session_duration = current_time - self.session_start
        fatigue_factor = min(1.5, 1 + (session_duration / 3600))
        if random.random() < 0.10:
            base_delay += random.uniform(5.0, 15.0)
        if random.random() < 0.01:
            base_delay += random.uniform(30.0, 120.0)
        total_delay = base_delay * fatigue_factor
        elapsed = current_time - self.last_request_time
        if elapsed < total_delay:
            additional_wait = total_delay - elapsed
            await asyncio.sleep(additional_wait)
        self.last_request_time = time.time()
        return total_delay

# === РАСШИРЕННЫЕ HEADERS ===
class SmartHeaders:
    def __init__(self):
        self.session_cookies = {}
        self.last_referer = None
        
    def get_headers(self, url: str, is_ajax: bool = False) -> dict:
        """Генерирует реалистичные headers"""
        ua = random.choice(REALISTIC_USER_AGENTS)
        headers = {
            'User-Agent': ua,
            'Accept-Language': random.choice(['en-US,en;q=0.9', 'en-US,en;q=0.9,ru;q=0.8', 'en-GB,en;q=0.9,en-US;q=0.8']),
            'Accept-Encoding': 'gzip, deflate, br', 'DNT': '1', 'Connection': 'keep-alive', 'Upgrade-Insecure-Requests': '1',
        }
        if is_ajax:
            headers['Accept'] = 'application/json, text/javascript, */*; q=0.01'
            headers['X-Requested-With'] = 'XMLHttpRequest'
        else:
            headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        if self.last_referer:
            headers['Referer'] = self.last_referer
        headers['Sec-Fetch-Dest'] = 'document' if not is_ajax else 'empty'
        headers['Sec-Fetch-Mode'] = 'navigate' if not is_ajax else 'cors'
        headers['Sec-Fetch-Site'] = 'none' if not self.last_referer else 'same-origin'
        if 'Chrome' in ua:
            headers['sec-ch-ua'] = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
            headers['sec-ch-ua-mobile'] = '?0'
            headers['sec-ch-ua-platform'] = '"Windows"'
        return headers
    
    def update_session(self, response_headers: dict, url: str):
        """Обновляет состояние сессии"""
        self.last_referer = url
        if 'Set-Cookie' in response_headers:
            cookie_value = response_headers['Set-Cookie'].split(';')[0]
            cookie_name, cookie_val = cookie_value.split('=', 1)
            self.session_cookies[cookie_name] = cookie_val
            
class WAFDetector:
    """Определяет типы WAF блокировок"""
    
    WAF_SIGNATURES = {
        'cloudflare_challenge': [
            r'checking your browser',
            r'cloudflare',
            r'cf-ray',
            r'__cf_bm',
            r'challenge-platform'
        ],
        'akamai_block': [
            r'reference #\d+\.\w+\.\d+',
            r'akamai',
            r'access denied'
        ],
        'generic_js_challenge': [
            r'please enable javascript',
            r'javascript is required',
            r'browser check',
            r'security check'
        ]
    }
    
    @staticmethod
    def detect_waf_type(response_text: str, headers: dict, status_code: int) -> tuple:
        """
        Возвращает (is_blocked, waf_type, needs_browser)
        """
        response_lower = response_text.lower()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        # Проверяем заголовки
        if 'server' in headers_lower:
            server = headers_lower['server']
            if 'cloudflare' in server:
                # Ищем JS challenge
                if any(re.search(pattern, response_lower) for pattern in WAFDetector.WAF_SIGNATURES['cloudflare_challenge']):
                    return True, 'cloudflare_challenge', True
            elif 'akamaighost' in server:
                return True, 'akamai_block', True
        
        # Проверяем статус коды
        if status_code in [403, 406, 429]:
            # Ищем признаки JS challenge
            if any(re.search(pattern, response_lower) for pattern in WAFDetector.WAF_SIGNATURES['generic_js_challenge']):
                return True, 'generic_js_challenge', True
            return True, 'http_block', False
        
        # Проверяем контент на JS challenges
        for waf_type, patterns in WAFDetector.WAF_SIGNATURES.items():
            if any(re.search(pattern, response_lower) for pattern in patterns):
                return True, waf_type, True
        
        return False, None, False
        
# ДОБАВИТЬ ЭТИ КЛАССЫ В ВАШ КОД (после WAFDetector, перед BrowserHandler)

class OptimizedBrowserHandler:
    """Единый браузер-хэндлер с блокировкой ненужных ресурсов"""
    
    def __init__(self, browser_semaphore: asyncio.Semaphore):
        self.browser = None
        self.context = None
        self.semaphore = browser_semaphore
        self.playwright = None
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'blocked_resources_count': 0
        }
    
    async def __aenter__(self):
        self.playwright = await async_playwright().start()
        
        # Оптимизированные аргументы для производительности
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=[
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-web-security',
                '--disable-features=VizDisplayCompositor',
                '--disable-gpu',
                '--disable-accelerated-2d-canvas',
                '--disable-software-rasterizer',
                '--memory-pressure-off',
                '--max_old_space_size=1024',  # 1GB лимит для V8
                '--disable-background-timer-throttling',
                '--disable-renderer-backgrounding',
                '--disable-backgrounding-occluded-windows',
                '--disable-ipc-flooding-protection'
            ]
        )
        
        # Создаем контекст с реалистичными настройками
        self.context = await self.browser.new_context(
            viewport={'width': 1366, 'height': 768},
            user_agent=random.choice(REALISTIC_USER_AGENTS),
            ignore_https_errors=True
        )
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
    
    async def fetch_with_browser(self, url: str, timeout: int = 45) -> tuple:
        """
        КЛЮЧЕВАЯ ОПТИМИЗАЦИЯ: блокируем ненужные ресурсы для экономии памяти и трафика
        """
        async with self.semaphore:
            page = None
            self.stats['total_requests'] += 1
            
            try:
                page = await self.context.new_page()
                
                # КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: блокируем все ненужные ресурсы
                async def block_resources(route):
                    resource_type = route.request.resource_type
                    blocked_types = {
                        "image", "media", "font", "other", 
                        "stylesheet"  # Блокируем CSS для экономии, JS нам важнее
                    }
                    
                    if resource_type in blocked_types:
                        self.stats['blocked_resources_count'] += 1
                        await route.abort()
                    else:
                        await route.continue_()
                
                await page.route("**/*", block_resources)
                
                # Загружаем страницу
                response = await page.goto(
                    url, 
                    wait_until='domcontentloaded',  # Не ждем полной загрузки
                    timeout=timeout * 1000
                )
                
                if not response:
                    return None, url, False
                
                # Умное ожидание: сначала короткое, потом проверяем на challenge
                await page.wait_for_timeout(random.randint(1500, 3000))
                content = await page.content()
                final_url = page.url
                
                # Проверяем на WAF challenge
                is_blocked, waf_type, needs_wait = WAFDetector.detect_waf_type(
                    content, dict(response.headers), response.status
                )
                
                if is_blocked and needs_wait:
                    print(f"[BROWSER] {waf_type} detected for {url}, waiting longer...")
                    await page.wait_for_timeout(random.randint(3000, 6000))
                    content = await page.content()
                    final_url = page.url
                
                self.stats['successful_requests'] += 1
                return content, final_url, True
                
            except Exception as e:
                print(f"[BROWSER] Error fetching {url}: {type(e).__name__}: {e}")
                self.stats['failed_requests'] += 1
                return None, url, False
            finally:
                if page and not page.is_closed():
                    await page.close()
                
                # Принудительная сборка мусора каждые 20 запросов
                if self.stats['total_requests'] % 20 == 0:
                    await self._force_gc()
    
    async def _force_gc(self):
        """Принудительная сборка мусора в браузере"""
        try:
            # Проходимся по всем страницам и вызываем сборку мусора
            for context in self.browser.contexts:
                for page in context.pages:
                    if not page.is_closed():
                        await page.evaluate('window.gc && window.gc()')
        except Exception:
            pass  # Игнорируем ошибки GC
    
    def print_stats(self):
        if self.stats['total_requests'] > 0:
            success_rate = (self.stats['successful_requests'] / self.stats['total_requests']) * 100
            print(f"[BROWSER STATS] Total requests: {self.stats['total_requests']}")
            print(f"[BROWSER STATS] Success rate: {success_rate:.1f}%")
            print(f"[BROWSER STATS] Blocked resources: {self.stats['blocked_resources_count']}")


class SmartCachingHybridFetcher:
    """Улучшенный HybridFetcher с умным кэшированием и retry логикой"""
    
    def __init__(self, session: aiohttp.ClientSession, browser_handler: OptimizedBrowserHandler, r: redis.Redis):
        self.session = session
        self.browser_handler = browser_handler
        self.redis = r
        self.stats = {
            'aiohttp_success': 0,
            'browser_fallback': 0,
            'total_blocked': 0,
            'total_requests': 0,
            'cache_hits': 0,
            'retry_successes': 0
        }
    
    def get_varied_headers(self, url: str, attempt: int = 0) -> dict:
        """Генерация вариативных заголовков с учетом попытки"""
        ua = random.choice(REALISTIC_USER_AGENTS)
        
        headers = {
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice([
                'en-US,en;q=0.9',
                'en-US,en;q=0.9,ru;q=0.8',
                'en-GB,en;q=0.9,en-US;q=0.8'
            ]),
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Вариации заголовков в зависимости от попытки
        if attempt > 0:
            headers['Cache-Control'] = random.choice(['no-cache', 'no-store', 'max-age=0'])
        
        if attempt > 1:
            headers['Pragma'] = 'no-cache'
            headers['X-Forwarded-For'] = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
        
        # Chrome-специфичные заголовки
        if 'Chrome' in ua:
            headers['sec-ch-ua'] = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
            headers['sec-ch-ua-mobile'] = '?0'
            headers['sec-ch-ua-platform'] = '"Windows"'
            headers['Sec-Fetch-Dest'] = 'document'
            headers['Sec-Fetch-Mode'] = 'navigate'
            headers['Sec-Fetch-Site'] = 'none'
        
        return headers
    
    async def fetch_hybrid(self, url: str, headers: dict, timeout: int = 30) -> tuple:
        """
        Основная функция с умным кэшированием и retry логикой
        """
        self.stats['total_requests'] += 1
        initial_content = None
        
        # Проверяем кэш браузерных ответов
        url_hash = hashlib.md5(url.encode()).hexdigest()
        cache_key = f"browser_cache:{url_hash}"
        
        try:
            cached_content = await self.redis.get(cache_key)
            if cached_content:
                self.stats['cache_hits'] += 1
                return cached_content.decode('utf-8', 'ignore'), url, False, None
        except Exception:
            pass  # Игнорируем ошибки кэша
        
        # Шаг 1: Умные retry для aiohttp
        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Вариативные заголовки для каждой попытки
                varied_headers = self.get_varied_headers(url, attempt)
                varied_headers.update(headers)  # Добавляем оригинальные заголовки
                
                # Прогрессивное увеличение timeout
                attempt_timeout = timeout + (attempt * 5)
                
                async with self.session.get(
                    url, 
                    headers=varied_headers, 
                    timeout=attempt_timeout, 
                    ssl=False, 
                    allow_redirects=True
                ) as resp:
                    
                    content = await resp.text(encoding='utf-8', errors='ignore')
                    initial_content = content
                    response_headers = dict(resp.headers)
                    status_code = resp.status
                    final_url = str(resp.url)
                    
                    # Специальная обработка rate limiting
                    if status_code == 429:
                        retry_after = response_headers.get('Retry-After', '5')
                        try:
                            wait_time = min(int(retry_after), 30)  # Максимум 30 сек
                        except ValueError:
                            wait_time = 5
                        
                        print(f"[RETRY] Rate limited. Waiting {wait_time}s (attempt {attempt + 1})")
                        await asyncio.sleep(wait_time + random.uniform(0, 2))
                        continue
                    
                    # Проверка на WAF блокировку
                    is_blocked, waf_type, needs_browser = WAFDetector.detect_waf_type(
                        content, response_headers, status_code
                    )
                    
                    if not is_blocked:
                        # Успех! Кэшируем результат на короткое время
                        try:
                            await self.redis.set(f"aiohttp_cache:{url_hash}", content.encode('utf-8'), ex=300)  # 5 мин
                        except Exception:
                            pass
                        
                        self.stats['aiohttp_success'] += 1
                        if attempt > 0:
                            self.stats['retry_successes'] += 1
                        return content, final_url, False, None
                    
                    # Если блокировка, но не нужен браузер (например, простой 403)
                    if not needs_browser:
                        if attempt < max_retries - 1:
                            # Пробуем с другими заголовками
                            delay = (2 ** attempt) + random.uniform(1, 3)
                            print(f"[RETRY] HTTP block detected. Retrying in {delay:.1f}s (attempt {attempt + 1})")
                            await asyncio.sleep(delay)
                            continue
                        else:
                            # Исчерпали попытки
                            self.stats['total_blocked'] += 1
                            return None, final_url, False, initial_content
                    
                    # Нужен браузер для JS challenge
                    break
                    
            except asyncio.TimeoutError:
                if attempt < max_retries - 1:
                    delay = random.uniform(2, 5) * (attempt + 1)
                    print(f"[RETRY] Timeout. Retrying in {delay:.1f}s (attempt {attempt + 1})")
                    await asyncio.sleep(delay)
                    continue
                else:
                    print(f"[RETRY] All aiohttp attempts failed for {url}")
                    break
            except Exception as e:
                if attempt < max_retries - 1:
                    delay = random.uniform(1, 3) * (attempt + 1)
                    await asyncio.sleep(delay)
                    continue
                else:
                    print(f"[RETRY] aiohttp completely failed for {url}: {e}")
                    break
        
        # Шаг 2: Fallback на браузер
        print(f"[HYBRID] Browser fallback for {url}")
        self.stats['browser_fallback'] += 1
        
        try:
            content, final_url, success = await self.browser_handler.fetch_with_browser(url, timeout + 15)
            
            if success and content:
                # Кэшируем браузерные результаты на дольше (они дороже получаются)
                try:
                    await self.redis.set(cache_key, content.encode('utf-8'), ex=1800)  # 30 мин
                except Exception:
                    pass
                
                return content, final_url, True, initial_content
        except Exception as e:
            print(f"[HYBRID] Browser fallback failed for {url}: {e}")
        
        return None, url, False, initial_content
    
    def print_stats(self):
        total = self.stats['total_requests']
        if total > 0:
            aiohttp_pct = (self.stats['aiohttp_success'] / total) * 100
            browser_pct = (self.stats['browser_fallback'] / total) * 100
            cache_hit_pct = (self.stats['cache_hits'] / total) * 100
            
            print(f"\n[HYBRID STATS] Total requests: {total}")
            print(f"[HYBRID STATS] aiohttp success: {self.stats['aiohttp_success']} ({aiohttp_pct:.1f}%)")
            print(f"[HYBRID STATS] Browser usage: {self.stats['browser_fallback']} ({browser_pct:.1f}%)")
            print(f"[HYBRID STATS] Cache hits: {self.stats['cache_hits']} ({cache_hit_pct:.1f}%)")
            print(f"[HYBRID STATS] Retry successes: {self.stats['retry_successes']}")


# Интеграционные функции
async def init_balanced_hybrid_system(session: aiohttp.ClientSession, r: redis.Redis, 
                                    max_browser_concurrency: int = 1) -> tuple:
    """Инициализация сбалансированной системы"""
    browser_semaphore = asyncio.Semaphore(max_browser_concurrency)
    browser_handler = OptimizedBrowserHandler(browser_semaphore)
    await browser_handler.__aenter__()
    
    hybrid_fetcher = SmartCachingHybridFetcher(session, browser_handler, r)
    
    return browser_handler, hybrid_fetcher

async def cleanup_balanced_system(browser_handler: OptimizedBrowserHandler, 
                                hybrid_fetcher: SmartCachingHybridFetcher):
    """Очистка ресурсов"""
    hybrid_fetcher.print_stats()
    browser_handler.print_stats()
    await browser_handler.__aexit__(None, None, None)

class BrowserHandler:
    """Обработчик для headless браузера"""
    
    def __init__(self):
        self.browser = None
        self.context = None
    
    async def __aenter__(self):
        self.playwright = await async_playwright().start()
        # Используем реальный браузер со всеми признаками
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=[
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-web-security',
                '--disable-features=VizDisplayCompositor'
            ]
        )
        
        # Создаем контекст с реальными характеристиками
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        )
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
    
    async def fetch_with_browser(self, url: str, timeout: int = 30) -> tuple:
        """
        Возвращает (content, final_url, success)
        """
        try:
            page = await self.context.new_page()
            
            # Ждем загрузки страницы и выполнения JS
            response = await page.goto(url, wait_until='domcontentloaded', timeout=timeout * 1000)
            
            if not response:
                return None, url, False
            
            # Ждем дополнительно для выполнения JS challenges
            await page.wait_for_timeout(random.randint(2000, 5000))
            
            # Проверяем, не перенаправило ли нас на challenge страницу
            current_url = page.url
            content = await page.content()
            
            # Если все еще challenge, ждем дольше
            is_blocked, waf_type, _ = WAFDetector.detect_waf_type(content, dict(response.headers), response.status)
            if is_blocked:
                print(f"[BROWSER] Still blocked after initial wait, trying longer wait for {url}")
                await page.wait_for_timeout(random.randint(5000, 10000))
                content = await page.content()
                current_url = page.url
            
            await page.close()
            return content, current_url, True
            
        except Exception as e:
            if 'page' in locals():
                await page.close()
            print(f"[BROWSER] Error fetching {url}: {e}")
            return None, url, False

class HybridFetcher:
    """Гибридный фетчер: aiohttp + браузер по необходимости"""
    
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.browser_handler = None
        self.stats = {
            'aiohttp_success': 0,
            'browser_fallback': 0,
            'total_blocked': 0,
            'total_requests': 0
        }
    
    async def fetch_hybrid(self, url: str, headers: dict, timeout: int = 30) -> tuple:
        """
        Главная функция гибридного фетча
        Возвращает (content, final_url, used_browser)
        """
        self.stats['total_requests'] += 1
        initial_content = None 
        
        # Шаг 1: Пробуем быстрый aiohttp
        try:
            async with self.session.get(url, headers=headers, timeout=timeout, ssl=False, allow_redirects=True) as resp:
                content = await resp.text(encoding='utf-8', errors='ignore')
                initial_content = content
                response_headers = dict(resp.headers)
                status_code = resp.status
                final_url = str(resp.url)
                
                # Анализируем ответ на предмет WAF блокировки
                is_blocked, waf_type, needs_browser = WAFDetector.detect_waf_type(
                    content, response_headers, status_code
                )
                
                if not is_blocked:
                    # Успех! Используем быстрый метод
                    self.stats['aiohttp_success'] += 1
                    return content, final_url, False, None
                
                # Обнаружена блокировка
                self.stats['total_blocked'] += 1
                print(f"[HYBRID] WAF detected: {waf_type} for {url}, needs_browser: {needs_browser}")
                
                if not needs_browser:
                    # HTTP блокировка без JS challenge - браузер не поможет
                    return None, final_url, False, initial_content
                
        except Exception as e:
            print(f"[HYBRID] aiohttp failed for {url}: {e}")
        
        # Шаг 2: Fallback на браузер для JS challenges
        print(f"[HYBRID] Falling back to browser for {url}")
        self.stats['browser_fallback'] += 1
        
        if not self.browser_handler:
            self.browser_handler = BrowserHandler()
            await self.browser_handler.__aenter__()
        
        try:
            content, final_url, success = await self.browser_handler.fetch_with_browser(url, timeout)
            if success:
                return content, final_url, True, initial_content 
        except Exception as e:
            print(f"[HYBRID] Browser fallback failed for {url}: {e}")
        
        return None, url, False, initial_content 
    
    async def close(self):
        """Закрытие браузера"""
        if self.browser_handler:
            await self.browser_handler.__aexit__(None, None, None)
    
    def print_stats(self):
        """Печать статистики"""
        total = self.stats['total_requests']
        if total > 0:
            aiohttp_pct = (self.stats['aiohttp_success'] / total) * 100
            browser_pct = (self.stats['browser_fallback'] / total) * 100
            blocked_pct = (self.stats['total_blocked'] / total) * 100
            
            print(f"\n[HYBRID STATS] Total requests: {total}")
            print(f"[HYBRID STATS] aiohttp success: {self.stats['aiohttp_success']} ({aiohttp_pct:.1f}%)")
            print(f"[HYBRID STATS] Browser fallback: {self.stats['browser_fallback']} ({browser_pct:.1f}%)")
            print(f"[HYBRID STATS] Total blocked: {self.stats['total_blocked']} ({blocked_pct:.1f}%)")

# Модификация для вашего основного кода
async def balanced_stealth_fetch_content(session: aiohttp.ClientSession, url: str, semaphore: asyncio.Semaphore, 
                                       args, timing, header_manager, hybrid_fetcher: SmartCachingHybridFetcher, 
                                       referer: str = None):
    """
    Сбалансированная замена для hybrid_stealth_fetch_content с умным кэшированием
    """
    async with semaphore:
        await timing.get_delay()
        headers = header_manager.get_headers(url)
        if referer:
            headers['Referer'] = referer
        
        try:
            content, final_url, used_browser, initial_content = await hybrid_fetcher.fetch_hybrid(url, headers)
            
            if content:
                if not used_browser:
                    header_manager.update_session({}, final_url)
                
                if args.debug:
                    method = "BROWSER" if used_browser else "AIOHTTP"
                    cache_status = "CACHED" if hybrid_fetcher.stats['cache_hits'] > 0 else ""
                    print(f"[DEBUG] {method} {cache_status} fetch success for {url}")
                
                return content, final_url, initial_content
            
        except Exception as e:
            if args.debug:
                print(f"[DEBUG][Balanced Fetch] Error for {url}: {e}")
    
    return None, url, None


# Original LinkFinder pattern (legacy support)
LINKFINDER_REGEX_STR = r"""
    (?:"|'|`)                                   # Match a starting quote: ", ' or `
    (                                           # Start capturing group 1
      /                                         # The path MUST start with a slash
      [a-zA-Z0-9_?&=\/\-\#\.]+                  # Match allowed characters in the path.
    )                                           # End capturing group 1
    (?:"|'|`)                                   # Match a closing quote: ", ' or `
"""

# Modern JavaScript patterns
MODERN_JS_PATTERNS = [
    # Template literals with variables: `${baseUrl}/api/users`
    r'`([^`]*\$\{[^}]+\}[^`]*)`',
    
    # Dynamic imports: import('./routes/' + pageName + '.js')
    r'import\s*\(\s*["\']([^"\']+)["\']',
    
    # Modern API patterns: '/api/v' + version + '/users'
    r'["\']([^"\']*\/api\/[^"\']*)["\']',
    
    # REST API endpoints: '/v2/accounts/me'
    r'["\'](\/(v\d+|api|rest|graphql)\/[^"\']+)["\']',
    
    # GraphQL specific
    r'["\']([^"\']*graphql[^"\']*)["\']',
    
    # Next.js API routes: '/api/users/[id]'
    r'["\']([^"\']*\/api\/[^"\']*\[[^\]]+\][^"\']*)["\']',
    
    # Webpack/Vite chunks: '/_next/static/chunks/[id].js'
    r'["\']([^"\']*\/_next\/[^"\']+)["\']',
    r'["\']([^"\']*\/chunks\/[^"\']+)["\']',
    r'["\']([^"\']*\/assets\/[^"\']+)["\']',
    
    # Service worker paths
    r'["\']([^"\']*\/sw\.js[^"\']*)["\']',
    r'["\']([^"\']*service-worker[^"\']*)["\']',
    
    # Dynamic path construction: baseUrl + '/users/' + id
    r'[+\s]["\']([^"\']*\/[^"\']+)["\']',
    
    # Fetch/axios calls: fetch('/api/data.json')
    r'(?:fetch|axios|xhr)\s*\(\s*["\']([^"\']+)["\']',
    
    # Route definitions: route: '/admin/dashboard'
    r'route\s*:\s*["\']([^"\']+)["\']',
    
    # URL constants: const API_URL = '/api/v2'
    r'(?:URL|PATH|ENDPOINT)\s*=\s*["\']([^"\']+)["\']',
]

LINKFINDER_REGEX = re.compile(LINKFINDER_REGEX_STR, re.VERBOSE)
SIMPLE_REGEX = re.compile(r"""(?:"|'|`)(/[a-zA-Z0-9_?&=\/\-\#\.]*)(?:"|'|`)""")
MODERN_REGEX_LIST = [re.compile(pattern, re.IGNORECASE) for pattern in MODERN_JS_PATTERNS]

# ... после MODERN_REGEX_LIST

# --- НОВЫЙ ЭТАП: Поиск API-ключей ---
API_KEY_PATTERNS = [
    # === ПРИВАТНЫЕ КЛЮЧИ (максимальный импакт, 100% точность) ===
    ('RSA Private Key', r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),
    ('SSH Private Key', r'-----BEGIN OPENSSH PRIVATE KEY-----'),
    ('PGP Private Key', r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    ('Firebase Admin SDK', r'"private_key":\s*"-----BEGIN PRIVATE KEY-----'),
    
    # === AWS (строгие паттерны) ===
    ('AWS Access Key ID', r'AKIA[A-Z0-9]{16}'),
    ('AWS Secret Key', r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)["\'\s]*[:=]["\'\s]*["\']([A-Za-z0-9/+=]{40})["\']'),
    
    # === GOOGLE CLOUD ===
    ('Google Cloud Service Account', r'"type":\s*"service_account"'),
    
    # === AZURE ===
    ('Azure Client Secret', r'(?:AZURE_CLIENT_SECRET|azure_client_secret)["\'\s]*[:=]["\'\s]*["\']([A-Za-z0-9\-\.~_]{32,})["\']'),
    
    # === GITHUB (высокая точность) ===
    ('GitHub PAT', r'ghp_[a-zA-Z0-9]{36,}'),
    ('GitHub OAuth', r'gho_[a-zA-Z0-9]{36,}'),
    ('GitHub App Token', r'ghs_[a-zA-Z0-9]{36,}'),
    ('GitHub Refresh', r'ghr_[a-zA-Z0-9]{36,}'),
    
    # === GITLAB ===
    ('GitLab PAT', r'glpat-[a-zA-Z0-9\-_]{20,}'),
    ('GitLab Runner', r'glrt-[a-zA-Z0-9\-_]{20,}'),
    
    # === ПЛАТЕЖИ (100% специфичные форматы) ===
    ('Stripe Live Secret', r'sk_live_[a-zA-Z0-9]{24,}'),
    ('Stripe Restricted', r'rk_live_[a-zA-Z0-9]{24,}'),
    ('Square Access Token', r'sq0atp-[a-zA-Z0-9\-_]{22,}'),
    ('Square Refresh Token', r'sq0csp-[a-zA-Z0-9\-_]{43,}'),
    ('Braintree Token', r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}'),
    
    # === МЕССЕНДЖЕРЫ (специфичные форматы) ===
    ('Slack Bot Token', r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}'),
    ('Slack Webhook', r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24,}'),
    ('Discord Bot Token', r'[MN][A-Za-z\d]{23,25}\.[A-Za-z\d]{6}\.[A-Za-z\d_-]{27,}'),
    ('Discord Webhook', r'https://discord(?:app)?\.com/api/webhooks/\d{17,19}/[A-Za-z0-9_-]{60,68}'),
    ('Telegram Bot', r'\d{8,10}:[A-Za-z0-9_-]{35}'),
    
    # === EMAIL (уникальные форматы) ===
    ('SendGrid', r'SG\.[a-zA-Z0-9\-_]{22,}\.[a-zA-Z0-9\-_]{43,}'),
    ('Mailgun', r'key-[a-f0-9]{32}'),
    ('Mailchimp', r'[a-f0-9]{32}-us\d{1,2}'),
    
    # === БАЗЫ ДАННЫХ (connection strings) ===
    ('MongoDB', r'mongodb(?:\+srv)?://[a-zA-Z0-9\-_]+:[^@\s]+@[a-zA-Z0-9\-_.]+'),
    ('Redis', r'redis://:[^@\s]+@[a-zA-Z0-9\-_.]+:\d+'),
    ('PostgreSQL', r'postgres(?:ql)?://[a-zA-Z0-9\-_]+:[^@\s]+@[a-zA-Z0-9\-_.]+'),
    
    # === HOSTING ===
    ('DigitalOcean', r'dop_v1_[a-f0-9]{64}'),
    
    # === TWILIO (специфичные префиксы) ===
    ('Twilio SID', r'AC[a-f0-9]{32}'),
    ('Twilio Auth', r'SK[a-f0-9]{32}'),
    
    # === GENERIC (только с ЯВНЫМИ именами переменных) ===
    ('OAuth Client Secret', r'(?:CLIENT_SECRET|client_secret)["\'\s]*[:=]["\'\s]*["\']([A-Za-z0-9\-_.~]{32,})["\']'),
    ('App Secret', r'(?:APP_SECRET|app_secret)["\'\s]*[:=]["\'\s]*["\']([A-Za-z0-9\-_.~]{32,})["\']'),
]
# Компилируем для производительности
COMPILED_API_KEY_PATTERNS = [(key_type, re.compile(pattern)) for key_type, pattern in API_KEY_PATTERNS]

def extract_api_keys(content: str):
    """Извлекает API ключи из контента"""
    found_keys = []
    # Используем сырой контент, так как beautifier может сломать длинные строки ключей
    for key_type, pattern in COMPILED_API_KEY_PATTERNS:
        matches = pattern.finditer(content)
        for match in matches:
            # Если в regex есть группа, берем ее, иначе - всю строку
            key_value = match.group(1) if match.groups() else match.group(0)
            
            # Дополнительная валидация
            if not any(placeholder in key_value.lower() for placeholder in 
                      ['xxx', 'your_', 'example', 'demo', 'test', '<', '>']):
                found_keys.append((key_type, key_value))
    return found_keys

# --- НОВЫЙ ЭТАП: Анализ Sourcemaps и комментариев ---

async def check_and_extract_sourcemap(session, js_url, content):
    """Проверяет и извлекает source map, возвращая оригинальный код"""
    sourcemap_match = re.search(r'//# sourceMappingURL=(.+)', content)
    if not sourcemap_match:
        return None
    
    sourcemap_ref = sourcemap_match.group(1).strip()
    
    sourcemap_content = None
    if sourcemap_ref.startswith('data:'):
        try:
            import base64
            encoded = sourcemap_ref.split(',')[1]
            decoded = base64.b64decode(encoded).decode('utf-8', 'ignore')
            sourcemap_content = json.loads(decoded)
        except Exception:
            return None
    else:
        sourcemap_url = urljoin(js_url, sourcemap_ref)
        try:
            async with session.get(sourcemap_url, timeout=30, ssl=False) as resp:
                if resp.status == 200:
                    # Используем content_type=None, чтобы обрабатывать неправильные заголовки
                    sourcemap_content = await resp.json(content_type=None)
        except Exception:
            return None

    if not sourcemap_content or 'sourcesContent' not in sourcemap_content:
        return None
    
    sources = []
    if 'sourcesContent' in sourcemap_content:
        for i, source_code in enumerate(sourcemap_content['sourcesContent']):
            if source_code:
                source_name = sourcemap_content['sources'][i] if i < len(sourcemap_content['sources']) else f"source_{i}"
                sources.append({'name': source_name, 'content': source_code})

    return {'sources': sources} if sources else None


# --- ЭТАП 1: Фильтры для ложных срабатываний (из v2) ---
FP_EXACT_MATCHES = {
    'application/json', 'application/xml', 'application/octet-stream', 'application/pdf',
    'application/x-www-form-urlencoded', 'multipart/form-data', 'text/html', 'text/plain',
    'text/xml', 'text/css', 'text/javascript', 'image/png', 'image/jpeg', 'image/gif',
    'image/webp', 'image/svg', 'image/x-icon', 'font/woff2', 'text/partytown', 'text/x-component',
    'http://www.w3.org/2000/svg', 'http://www.w3.org/1999/xhtml', 'http://www.w3.org/1999/xlink',
    'http://www.w3.org/XML/1998/namespace', 'http://www.w3.org/2000/xmlns/', 'http://www.w3.org/1998/Math/MathML',
    'http://schema.org/', 'https://schema.org',
}

FP_SUBSTRINGS = ['node_modules', '.scss', '.ts', '.tsx', '.jsx', '.vue', 'source/src', '.js', '/blog/', '/ads/']
FP_ENDS_WITH = ['/index', '/core', '/utils', '/vendor.js', '/runtime.js', '/polyfills.js', '/styles.css']
FP_REGEX_PATTERNS = [
    re.compile(r'^(?:America|Europe|Asia|Africa|Australia|Atlantic|Pacific|Indian|Etc)/[A-Za-z_]+(?:\|[A-Za-z_/]+)*$'),
    re.compile(r'^(?:[A-Z]{2,4}[/]){2,}[A-Z]{2,4}$'), re.compile(r'^\/\d{3}$'),
    re.compile(r'(?:/i18n|/locale|/locales)'), re.compile(r'^[./]*[a-z]{2}(?:-[A-Z]{2})?(?:\.js(?:on)?)?$'),
    re.compile(r'-\w{8,}\.(?:css|css\.map)$'), re.compile(r'chunk-[A-Z0-9]{8,}\.js$'),
    re.compile(r'^[A-Za-z0-9+=]{20,}$'),
    re.compile(r'\.(svg|jpg|jpeg|png|webp|gif|ico|woff|woff2|ttf|eot|css|map|mp4|mp3|wav|d\.ts|html|htm|xml)$', re.IGNORECASE),
    re.compile(r'^[^a-zA-Z]+$'), re.compile(r'/[a-zA-Z]{2}-[a-zA-Z]{2}/'),
]

def filter_false_positives(endpoints: list, args: argparse.Namespace) -> list:
    if args.debug: print(f"[DEBUG][FP Filter] Starting FP filtering for {len(endpoints)} endpoints...")
    filtered = []
    for ep in endpoints:
        ep_lower = ep.lower()
        if ep.startswith(('http:', 'https:', '//')) or ep in {'/', './', '../'} or ep_lower in FP_EXACT_MATCHES: continue
        if any(sub in ep_lower for sub in FP_SUBSTRINGS) or any(ep_lower.endswith(suffix) for suffix in FP_ENDS_WITH): continue
        if any(p.search(ep) for p in FP_REGEX_PATTERNS): continue
        if '/' in ep and sum(1 for c in ep if c.isupper()) / len(ep.replace('/', '')) > 0.3: continue
        if len(ep) < 3 and ep.isalpha(): continue
        filtered.append(ep)
    if args.debug: print(f"[DEBUG][FP Filter] Finished FP filtering. Kept {len(filtered)} of {len(endpoints)} endpoints.")
    return filtered

# --- ЭТАП 2: Whitelist-фильтр для интересных эндпоинтов (из v3) ---
API_WHITELIST_PATTERNS = [
    # === API паттерны ===
    r'.*\bapi\b.*', r'.*\brest\b.*', r'.*\bgraphql\b.*', r'.*/v\d{1,2}(/.*)?$', r'.*\bservice\b.*',
    r'.*\bservices\b.*', r'.*\bmicroservice\b.*', r'.*\bws\b.*', r'.*\bwebservice\b.*', r'.*\brpc\b.*',
    r'.*\bjsonrpc\b.*', r'.*\bxmlrpc\b.*', r'.*\bsoap\b.*', r'.*\bodata\b.*',
    # === Современные фреймворки ===
    r'.*next.*api.*', r'.*nuxt.*api.*', r'.*\bstrapi\b.*', r'.*\bdirectus\b.*', r'.*\bghost\b.*',
    r'.*wp-json.*', r'.*\bwp\b.*',
    # === Admin и панели управления ===
    r'.*\badmin\b.*', r'.*\badministrator\b.*', r'.*\bmanagement\b.*', r'.*\bmanager\b.*',
    r'.*\bdashboard\b.*', r'.*\bpanel\b.*', r'.*\bcontrol\b.*', r'.*\bbackend\b.*', r'.*\bbackoffice\b.*',
    r'.*\bcp\b.*', r'.*\bconsole\b.*',
    # === Внутренние и служебные ===
    r'.*\binternal\b.*', r'.*\bprivate\b.*', r'.*\bsystem\b.*', r'.*\bsys\b.*', r'.*\bcore\b.*',
    r'.*\bconfig\b.*', r'.*\bconfiguration\b.*', r'.*\bsettings\b.*', r'.*\bpreferences\b.*', r'.*\boptions\b.*',
    # === Аутентификация и авторизация ===
    r'.*\bauth\b.*', r'.*\bauthentication\b.*', r'.*\bauthorization\b.*', r'.*\blogin\b.*', r'.*\blogout\b.*',
    r'.*\bsignin\b.*', r'.*\bsignout\b.*', r'.*\bsignup\b.*', r'.*\bregister\b.*', r'.*\boauth\b.*',
    r'.*\boauth2\b.*', r'.*\bsaml\b.*', r'.*\bsso\b.*', r'.*\bopenid\b.*', r'.*\bjwt\b.*', r'.*\btoken\b.*',
    r'.*\brefresh\b.*',
    # === Файлы и загрузки ===
    r'.*\bupload\b.*', r'.*\buploads\b.*', r'.*\bdownload\b.*', r'.*\bdownloads\b.*', r'.*\bfile\b.*',
    r'.*\bfiles\b.*', r'.*\bresources\b.*', r'.*\bcontent\b.*', r'.*\battachments\b.*', r'.*\bdocuments\b.*',
    # === Debug и мониторинг ===
    r'.*\bdebug\b.*', r'.*\btrace\b.*', r'.*\bhealth\b.*', r'.*\bstatus\b.*', r'.*\bping\b.*',
    r'.*\bmetrics\b.*', r'.*\bstats\b.*', r'.*\bstatistics\b.*', r'.*\bmonitor\b.*', r'.*\bmonitoring\b.*',
    r'.*\bactuator\b.*', r'.*\binfo\b.*',
    # === Базы данных ===
    r'.*\bdb\b.*', r'.*\bdatabase\b.*', r'.*\bsql\b.*', r'.*\bquery\b.*', r'.*\bsearch\b.*',
    r'.*\belastic\b.*', r'.*\bes\b.*', r'.*\bmongo\b.*', r'.*\bredis\b.*', r'.*\binflux\b.*',
    # === Интеграции и веб-хуки ===
    r'.*\bwebhook\b.*', r'.*\bwebhooks\b.*', r'.*\bcallback\b.*', r'.*\bcallbacks\b.*', r'.*\bintegration\b.*',
    r'.*\bintegrations\b.*', r'.*\bconnect\b.*', r'.*\bsync\b.*', r'.*\bnotify\b.*', r'.*\bnotification\b.*',
    r'.*\bnotifications\b.*',
    # === Мобильные API ===
    r'.*\bmobile\b.*', r'.*\bapp\b.*', r'.*\bandroid\b.*', r'.*\bios\b.*', r'.*\bdevice\b.*', r'.*\bdevices\b.*',
    # === Тестовые и dev окружения ===
    r'.*\btest\b.*', r'.*\btesting\b.*', r'.*\bdev\b.*', r'.*\bdevelop\b.*', r'.*\bdevelopment\b.*',
    r'.*\bstage\b.*', r'.*\bstaging\b.*', r'.*\bsandbox\b.*', r'.*\bdemo\b.*', r'.*\bprototype\b.*',
    r'.*\bbeta\b.*', r'.*\balpha\b.*', r'.*\bpreview\b.*',
    # === Специальные форматы ===
    r'.*\.json(\?.*)?$', r'.*\.xml(\?.*)?$', r'.*\.rss(\?.*)?$', r'.*\.atom(\?.*)?$', r'.*\.txt(\?.*)?$',
    # === Платежи и e-commerce ===
    r'.*\bpayment\b.*', r'.*\bpayments\b.*', r'.*\bbilling\b.*', r'.*\binvoice\b.*', r'.*\binvoices\b.*',
    r'.*\border\b.*', r'.*\borders\b.*', r'.*\bcart\b.*', r'.*\bcheckout\b.*', r'.*\bsubscription\b.*',
    r'.*\bsubscriptions\b.*',
    # === Пользователи и профили ===
    r'.*\buser\b.*', r'.*\busers\b.*', r'.*\bprofile\b.*', r'.*\bprofiles\b.*', r'.*\baccount\b.*',
    r'.*\baccounts\b.*', r'.*\bmember\b.*', r'.*\bmembers\b.*', r'.*\bcustomer\b.*', r'.*\bcustomers\b.*',
    # === Аналитика и отчеты ===
    r'.*\banalytics\b.*', r'.*\breport\b.*', r'.*\breports\b.*', r'.*\bexport\b.*', r'.*\bimport\b.*',
    r'.*\bbackup\b.*', r'.*\brestore\b.*',
    # === Безопасность ===
    r'.*\bsecurity\b.*', r'.*\bcsrf\b.*', r'.*\bxss\b.*', r'.*rate-limit.*', r'.*\bthrottle\b.*',
    # === Специфичные паттерны ===
    r'.*\bproxy\b.*', r'.*\btunnel\b.*', r'.*\bbridge\b.*', r'.*\bgateway\b.*', r'.*\bendpoint\b.*',
    r'.*\broute\b.*', r'.*\brouter\b.*',
    # === Дополнительные интересные паттерны ===
    r'.*\bemail\b.*', r'.*\bmail\b.*', r'.*\bpassword\b.*', r'.*\bpwd\b.*', r'.*\bsession\b.*',
    r'.*\bsessions\b.*', r'.*\bcookie\b.*', r'.*\bcookies\b.*', r'.*\bvalidate\b.*', r'.*\bvalidation\b.*',
    r'.*\berror\b.*', r'.*\berrors\b.*', r'.*\blogger\b.*', r'.*\blogging\b.*', r'.*\blogs\b.*',
]

DYNAMIC_PATTERNS = [
    # Template literals
    (re.compile(r'\$\{[^}]+\}'), '{dynamic}'),
    
    # Конкатенация со строками
    (re.compile(r"['\"]([^'\"]*)['\"] *\+ *[a-zA-Z_][\w]*"), r'\1{dynamic}'),
    
    # Express/Router style параметры
    (re.compile(r':([a-zA-Z_][\w]*)'), '{dynamic}'),
    
    # Bracket notation параметры
    (re.compile(r'\[([a-zA-Z_][\w]*)\]'), '{dynamic}'),
    
    # Чужие плейсхолдеры в фигурных скобках
    (re.compile(r'\{[a-zA-Z_][\w]*\}'), '{dynamic}'),
]

# Компилируем все паттерны для производительности
COMPILED_WHITELIST_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in API_WHITELIST_PATTERNS]

# --- НОВЫЙ ЭТАП: Ультимативная предварительная фильтрация и санация ---

# Regex для очистки динамических частей `${...}` и шаблонных строк `...`
DYNAMIC_PART_REGEX = re.compile(r'\$\{[^}]+\}')
TEMPLATE_LITERAL_REGEX = re.compile(r'`[^`]*`')

# Более точные regex-паттерны для мусора с использованием якорей (^, $)
SANITIZER_REGEX_PATTERNS = [
    re.compile(r'^[^/]*\{[^}]*:[^}]*\}[^/]*$'),  # CSS property:value блоки
    re.compile(r'.*!important.*', re.IGNORECASE),
    re.compile(r'^\s*/\*.*\*/\s*$'),             # Полные CSS комментарии
    re.compile(r'^\s*//.*$'),                    # Полные JS комментарии
    re.compile(r'^\s*<!--.*-->\s*$'),            # Полные HTML комментарии
    re.compile(r'^\s*(?:\*\s*)?(?:license|copyright|mit license|apache|gpl|bsd).*', re.IGNORECASE),
    re.compile(r'.*elements are self-closing.*', re.IGNORECASE),
    re.compile(r'.*Refer to our API for more information.*', re.IGNORECASE),
    re.compile(r'.*@(?:webkit|moz|ms|o)-.*'),    # CSS vendor prefixes
    re.compile(r'.*@(?:keyframes|media|import|charset).*'),  # CSS at-rules
    re.compile(r'^.{150,}$'),                    # Слишком длинные строки
    re.compile(r'^\.(?:v-|scoped-|css-).*'),     # CSS классы
    re.compile(r'^[A-Za-z0-9+/]{40,}={0,2}$'),  # Base64
    re.compile(r'^[A-Fa-f0-9]{32,}$'),          # Hex hashes
]

# CSS-специфичные подстроки для контекстной проверки
CSS_CONTEXT_SUBSTRINGS = [
    'margin-left', 'margin-right', 'padding-', 'font-size', 'background-color',
    'border-', 'text-align', 'display:block', 'position:absolute', 'z-index:',
    'transform:', 'transition:', 'animation:', '@keyframes', '.scoped-vuetify'
]

def ultimate_pre_filter_and_sanitize(endpoints: list, args: argparse.Namespace) -> list:
    """Улучшенная версия с множественными паттернами динамики"""
    if args.debug:
        print(f"[DEBUG][Ultimate Sanitizer] Starting pre-filtering for {len(endpoints)} raw matches...")
    
    sanitized_endpoints = set()
    
    for ep in endpoints:
        original_ep = ep
        
        # 1. Удаляем template literals обертки
        ep = TEMPLATE_LITERAL_REGEX.sub('', ep).strip()
        if not ep:
            continue
        
        # 2. НОВАЯ ЛОГИКА: Применяем ВСЕ паттерны динамических частей
        ep_sanitized = ep
        for pattern, replacement in DYNAMIC_PATTERNS:
            ep_sanitized = pattern.sub(replacement, ep_sanitized)
        
        # 3. Проверка на незакрытые/некорректные скобки
        # Проверяем баланс фигурных скобок
        open_braces = ep_sanitized.count('{')
        close_braces = ep_sanitized.count('}')
        
        if open_braces != close_braces:
            if args.debug:
                print(f"[DEBUG][Sanitizer] Rejected unbalanced braces: {original_ep}")
            continue
        
        # 4. Проверка на частичные плейсхолдеры (например, {dynamic без })
        if '{dynamic' in ep_sanitized and '{dynamic}' not in ep_sanitized:
            if args.debug:
                print(f"[DEBUG][Sanitizer] Rejected incomplete placeholder: {original_ep}")
            continue
        
        # ... остальные проверки из оригинальной функции ...
        
        # 5. Применяем остальные regex фильтры
        if any(pattern.search(ep) for pattern in SANITIZER_REGEX_PATTERNS):
            if args.debug: 
                print(f"[DEBUG][Ultimate Sanitizer] Rejected by regex: {original_ep}")
            continue
        
        # 6. CSS контекстная фильтрация
        ep_lower = ep_sanitized.lower()
        is_css_context = any(css_sub in ep_lower for css_sub in CSS_CONTEXT_SUBSTRINGS)
        if is_css_context and not ep_sanitized.startswith('/'):
            if args.debug: 
                print(f"[DEBUG][Ultimate Sanitizer] Rejected CSS context: {original_ep}")
            continue
        
        # 7. Эвристические проверки
        if not ep_sanitized.startswith('/'):
            if '/' in ep_sanitized and not ep_sanitized.startswith('http'):
                ep_sanitized = '/' + ep_sanitized.lstrip('/')
            else:
                if args.debug: 
                    print(f"[DEBUG][Ultimate Sanitizer] Invalid path format: {original_ep}")
                continue
        
        path_part = ep_sanitized.replace('/', '').replace('{dynamic}', '')
        if not path_part:
            continue
        
        # Соотношение заглавных букв
        if len(path_part) > 3:
            upper_ratio = sum(1 for c in path_part if c.isupper()) / len(path_part)
            if upper_ratio > 0.5:
                if args.debug: 
                    print(f"[DEBUG][Ultimate Sanitizer] Rejected by upper case ratio {upper_ratio:.2f}: {original_ep}")
                continue
        
        # Соотношение цифр
        if len(path_part) > 2:
            digit_ratio = sum(1 for c in path_part if c.isdigit()) / len(path_part)
            if digit_ratio > 0.8:
                if args.debug: 
                    print(f"[DEBUG][Ultimate Sanitizer] Rejected by digit ratio {digit_ratio:.2f}: {original_ep}")
                continue
        
        # 8. Финальная очистка
        ep_cleaned = ep_sanitized.strip('\'".,;()[]{}').rstrip('/')
        if not ep_cleaned or ep_cleaned == '/' or len(ep_cleaned) < 2:
            continue
        
        sanitized_endpoints.add(ep_cleaned)
    
    final_list = sorted(list(sanitized_endpoints))
    if args.debug:
        print(f"[DEBUG][Ultimate Sanitizer] Finished pre-filtering. Kept {len(final_list)} of {len(endpoints)}.")
    return final_list

def filter_whitelist_endpoints(endpoints: list, args: argparse.Namespace) -> list:
    """
    Новая функция фильтрации по whitelist паттернам
    Оставляет только эндпоинты, соответствующие интересным паттернам
    """
    if args.debug:
        print(f"[DEBUG][Whitelist Filter] Starting whitelist filtering for {len(endpoints)} endpoints...")
    filtered = []
    for ep in endpoints:
        if not ep or len(ep) < 2 or not ep.startswith('/'): continue
        is_interesting = any(pattern.search(ep) for pattern in COMPILED_WHITELIST_PATTERNS)
        if is_interesting:
            filtered.append(ep)
            if args.debug: print(f"[DEBUG][Whitelist Filter] Match found: {ep}")
    if args.debug:
        print(f"[DEBUG][Whitelist Filter] Finished whitelist filtering. Kept {len(filtered)} of {len(endpoints)} endpoints.")
    return filtered

# --- CHECKPOINT FUNCTIONS ---
async def save_checkpoint(r: redis.Redis, cycle_id: str, batch_index: int, processed_files: list):
    """Save checkpoint data to Redis"""
    checkpoint_data = {
        'batch_index': batch_index,
        'processed_files': processed_files,
        'timestamp': time.time()
    }
    key = CHECKPOINT_KEY_TPL.format(cycle_id=cycle_id)
    await r.set(key, json.dumps(checkpoint_data), ex=3600)  # Expire after 1 hour

async def load_checkpoint(r: redis.Redis, cycle_id: str):
    """Load checkpoint data from Redis"""
    key = CHECKPOINT_KEY_TPL.format(cycle_id=cycle_id)
    data = await r.get(key)
    if data:
        return json.loads(data)
    return None

async def clear_checkpoint(r: redis.Redis, cycle_id: str):
    """Clear checkpoint data"""
    key = CHECKPOINT_KEY_TPL.format(cycle_id=cycle_id)
    await r.delete(key)

# --- CONTENT DEDUPLICATION ---
def calculate_content_hash(content: str) -> str:
    """Calculate MD5 hash of content for deduplication"""
    return hashlib.md5(content.encode('utf-8')).hexdigest()

async def is_content_processed(r: redis.Redis, content_hash: str) -> bool:
    """Check if content with this hash was already processed"""
    key = CONTENT_HASH_KEY_TPL.format(hash=content_hash)
    return await r.exists(key)

async def mark_content_processed(r: redis.Redis, content_hash: str):
    """Mark content hash as processed"""
    key = CONTENT_HASH_KEY_TPL.format(hash=content_hash)
    await r.set(key, "1", ex=86400)  # Expire after 24 hours


def find_all_js_sources(html_content: str, base_url: str, source_host: str):
    """
    Извлекает как внешние JS-файлы, так и интересные inline-скрипты.
    Возвращает список кортежей для добавления в очередь анализа.
    Использует хеш контента для стабильной идентификации inline-скриптов.
    """
    if not html_content:
        return []
    
    tasks_for_queue = []
    soup = BeautifulSoup(html_content, 'lxml')

    # 1. Внешние JS файлы
    for tag in soup.find_all(['script', 'link']):
        src = tag.get('src') or tag.get('href')
        if src and ('.js' in src or 'javascript' in src):
            full_url = urljoin(base_url, src)
            # --- НОВАЯ СТРОКА: ПРОВЕРКА ПО БЛОК-ЛИСТУ ---
            if any(blocked in urlparse(full_url).netloc for blocked in SCRIPT_BLOCKLIST_DOMAINS):
                continue # Пропускаем заблокированный скрипт
            # Формат задачи: (URL, хост, реферер, контент) - контент None, его надо скачать
            tasks_for_queue.append((full_url, source_host, base_url, None))

    # 2. Inline-скрипты
    for script in soup.find_all('script'):
        if not script.get('src'):  # Это inline script
            script_content = script.string
            # Ищем только в достаточно больших и потенциально интересных скриптах
            if script_content and len(script_content) > 100 and any(
                keyword in script_content for keyword in 
                ['window.config', 'window.ENV', 'apiUrl', 'apiKey', 'endpoint', 'accessToken', 'graphql']
            ):
                # --- ИСПРАВЛЕНИЕ: ИСПОЛЬЗУЕМ ХЕШ ДЛЯ URL ---
                script_hash = hashlib.md5(script_content.encode('utf-8')).hexdigest()
                # Создаем уникальный и стабильный URL на основе контента
                virtual_url = f"{base_url}#inline-script-md5-{script_hash[:16]}"
                # --- КОНЕЦ ИСПРАВЛЕНИЯ ---
                
                # Формат задачи: (URL, хост, реферер, контент) - контент уже есть!
                tasks_for_queue.append((virtual_url, source_host, base_url, script_content))
                
    return tasks_for_queue

async def crawl_for_js_links(session: aiohttp.ClientSession, base_url: str, semaphore: asyncio.Semaphore, 
                           js_queue: asyncio.Queue, pbar_crawl: tqdm, analyzed_urls: set, args: argparse.Namespace, 
                           timing: HumanLikeTiming, header_manager: SmartHeaders, hybrid_fetcher):
    try:
        source_host = urlparse(base_url).hostname
        if not source_host: 
            return

        final_html_content, final_url, initial_html_content = await balanced_stealth_fetch_content(
            session, base_url, semaphore, args, timing, header_manager, hybrid_fetcher, referer=base_url
        )

        if not final_html_content and not initial_html_content: return

        # Используем set для автоматической дедупликации URL-ов
        found_tasks = set()

        # Парсим оба HTML, если они есть
        if initial_html_content:
            tasks = find_all_js_sources(initial_html_content, base_url, source_host)
            for task in tasks: found_tasks.add(task)
            
        if final_html_content:
            tasks = find_all_js_sources(final_html_content, final_url, source_host)
            for task in tasks: found_tasks.add(task)

        # Добавляем уникальные задачи в очередь
        for task in found_tasks:
            url_to_check = task[0] # URL задачи
            if url_to_check not in analyzed_urls:
                await js_queue.put(task)
                analyzed_urls.add(url_to_check)
                
    except Exception as e: 
        print(f"\n[!] Crawler error for {base_url}: {e}", file=sys.stderr)
    finally: 
        pbar_crawl.update(1)
        
# Полная, готовая к использованию версия функции
async def fetch_js_only(
    session: aiohttp.ClientSession, 
    url: str, 
    semaphore: asyncio.Semaphore, 
    args: argparse.Namespace,
    r: redis.Redis,  # <-- Добавляем Redis клиент
    referer: str = None
):
    """
    Умный и быстрый фетчер для JS-файлов с экономией трафика.
    Использует ETag/Last-Modified для проверки изменений без скачивания.
    Возвращает (content, is_new_content).
    """
    async with semaphore:
        headers = {
            'User-Agent': random.choice(REALISTIC_USER_AGENTS),
            'Accept': 'application/javascript, */*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        }
        if referer:
            headers['Referer'] = referer

        # --- НАЧАЛО ЛОГИКИ ЭКОНОМИИ ТРАФИКА ---
        url_hash = hashlib.md5(url.encode()).hexdigest()
        meta_key = f"js_meta:{url_hash}"

        try:
            # Получаем сохраненные ETag и Last-Modified из Redis
            cached_meta = await r.hgetall(meta_key)
            if cached_meta:
                if 'etag' in cached_meta:
                    headers['If-None-Match'] = cached_meta['etag']
                if 'last_modified' in cached_meta:
                    headers['If-Modified-Since'] = cached_meta['last_modified']
        except redis.RedisError as e:
            if args.debug:
                print(f"[DEBUG][Redis] Error getting meta for {url}: {e}")
            cached_meta = {}
        # --- КОНЕЦ ЛОГИКИ ЭКОНОМИИ ТРАФИКА ---

        try:
            async with session.get(url, headers=headers, timeout=NORMAL_TIMEOUT, ssl=False, allow_redirects=True) as resp:
                
                # --- ОБРАБОТКА ОТВЕТА СЕРВЕРА ---
                if resp.status == 304:  # 304 Not Modified
                    if args.debug:
                        print(f"[DEBUG][HTTP 304] Content not changed for {url}. Traffic saved.")
                    # Контент не изменился, возвращаем None, чтобы пропустить анализ
                    return None, False

                if resp.status == 200:
                    content_type = resp.headers.get('Content-Type', '').lower()
                    if 'javascript' in content_type or 'application/x-javascript' in content_type:
                        content = await resp.text(encoding='utf-8', errors='ignore')
                        
                        # Сохраняем новые ETag и Last-Modified для будущих проверок
                        new_etag = resp.headers.get('ETag')
                        new_last_modified = resp.headers.get('Last-Modified')
                        
                        pipe = r.pipeline()
                        if new_etag:
                            pipe.hset(meta_key, 'etag', new_etag)
                        if new_last_modified:
                            pipe.hset(meta_key, 'last_modified', new_last_modified)
                        
                        if pipe.commands:
                           pipe.expire(meta_key, 86400 * 7) # Храним метаданные неделю
                           await pipe.execute()

                        return content, True
                
                return None, False

        except Exception as e:
            if args.debug:
                print(f"[JS_FETCHER_FAIL] Failed to get {url}: {type(e).__name__}")
            return None, False

def parser_file(content: str, args: argparse.Namespace):
    if not content: return []
    if args.debug: print(f"[DEBUG][Parser] Processing content of length {len(content)}")
    
    try:
        beautified_content = jsbeautifier.beautify(content) if len(content) <= 1000000 else content.replace(";",";\r\n").replace(",",",\r\n")
    except Exception as e:
        if args.debug: print(f"[DEBUG][Parser] Beautification failed: {e}, using raw content")
        beautified_content = content
    
    matches = set()
    
    # Original patterns
    matches.update(m.group(1).strip() for m in LINKFINDER_REGEX.finditer(beautified_content) if m.group(1))
    matches.update(m.group(1).strip() for m in SIMPLE_REGEX.finditer(beautified_content) if m.group(1))
    matches.update(m.group(1).strip() for m in LINKFINDER_REGEX.finditer(content) if m.group(1))
    matches.update(m.group(1).strip() for m in SIMPLE_REGEX.finditer(content) if m.group(1))
    
    # Modern JavaScript patterns
    for regex in MODERN_REGEX_LIST:
        for match in regex.finditer(beautified_content):
            endpoint = match.group(1).strip()
            if endpoint and endpoint.startswith('/'):
                matches.add(endpoint)
        for match in regex.finditer(content):
            endpoint = match.group(1).strip() 
            if endpoint and endpoint.startswith('/'):
                matches.add(endpoint)
    
    if args.debug: print(f"[DEBUG][Parser] Found {len(matches)} unique endpoints")
    return [ep for ep in matches if ep]




# === УМНЫЙ RETRY С BACKOFF ===
async def smart_fetch_with_retry(session, url: str, headers: dict, max_retries: int = 3):
    """Fetch с умным retry и exponential backoff"""
    for attempt in range(max_retries):
        try:
            timeout = 10 + (attempt * 5)
            async with session.get(url, headers=headers, timeout=timeout, ssl=False) as resp:
                if resp.status == 429:
                    delay = (2 ** attempt) * random.uniform(5, 10)
                    print(f"[WAF] Rate limit hit. Waiting {delay:.1f}s before retry {attempt+1}")
                    await asyncio.sleep(delay)
                    continue
                elif resp.status in {403, 406}:
                    if attempt < max_retries - 1:
                        delay = random.uniform(2, 5)
                        print(f"[WAF] Possible WAF block (status {resp.status}). Long delay {delay:.1f}s")
                        await asyncio.sleep(delay)
                        continue
                content = await resp.text(encoding='utf-8', errors='ignore')
                return content, str(resp.url), dict(resp.headers)
        except asyncio.TimeoutError:
            if attempt < max_retries - 1:
                delay = random.uniform(10, 30)
                await asyncio.sleep(delay)
                continue
        except Exception as e:
            if attempt < max_retries - 1:
                delay = random.uniform(5, 15)
                await asyncio.sleep(delay)
                continue
    return None, url, {}


def read_urls_from_file(filepath: str):
    if not os.path.exists(filepath): sys.exit(f"[!] Input file not found: {filepath}")
    with open(filepath, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and line.startswith('http')]

async def send_notify_alert_async(message: str, config_path: str = None):
    command = ['notify', '-bulk']
    if config_path: command.extend(['-pc', config_path])
    try:
        proc = await asyncio.create_subprocess_exec(*command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        _, stderr = await proc.communicate(input=message.encode())
        if proc.returncode == 0: print("[+] Notification sent successfully via notify.")
        else: print(f"[!] Error sending notification via notify: {stderr.decode().strip()}", file=sys.stderr)
    except Exception as e: print(f"[!] An exception occurred while sending notification: {e}", file=sys.stderr)
    
# --- НОВЫЙ ЭТАП: Умный пробинг динамических эндпоинтов ---

# Наборы тестовых значений для разных типов параметров
DYNAMIC_TEST_VALUES = {
    'numeric_id': ['1', '123', '0', '999999'],
    'uuid': ['00000000-0000-0000-0000-000000000000', '123e4567-e89b-12d3-a456-426614174000'],
    'string_id': ['admin', 'user', 'test', 'me', 'current'],
    'hash': ['d41d8cd98f00b204e9800998ecf8427e', 'abc123'],
    'email': ['admin@example.com', 'test@test.com'],
    'filename': ['config.json', 'data.xml', 'backup.sql'],
    'version': ['v1', 'v2', 'latest', '1.0'],
}

def detect_parameter_type(endpoint_context):
    """Определяет наиболее вероятный тип параметра на основе контекста endpoint'а."""
    endpoint_lower = endpoint_context.lower()
    if any(word in endpoint_lower for word in ['user', 'account', 'profile', 'customer', 'member', 'id']): return 'numeric_id'
    if any(word in endpoint_lower for word in ['file', 'document', 'attachment', 'upload', 'download']): return 'filename'
    if any(word in endpoint_lower for word in ['version', 'api', 'v']): return 'version'
    if any(word in endpoint_lower for word in ['email', 'mail', 'notification']): return 'email'
    if any(word in endpoint_lower for word in ['uuid', 'guid', 'session', 'token']): return 'uuid'
    return 'numeric_id' # По умолчанию - числовые ID

def generate_probe_endpoints(sanitized_endpoint, max_variants=2):
    """
    Генерирует endpoints для пробинга с валидацией
    """
    # Проверка на корректность плейсхолдера
    if '{' in sanitized_endpoint or '}' in sanitized_endpoint:
        # Если есть скобки, они должны быть только в виде {dynamic}
        if sanitized_endpoint.count('{dynamic}') != sanitized_endpoint.count('{'):
            # Некорректный формат - возвращаем как есть, но с предупреждением
            print(f"[WARNING] Malformed dynamic placeholder: {sanitized_endpoint}")
            return [(sanitized_endpoint, f"{sanitized_endpoint} (malformed)")]
    
    if '{dynamic}' not in sanitized_endpoint:
        return [(sanitized_endpoint, sanitized_endpoint)]
    
    param_type = detect_parameter_type(sanitized_endpoint)
    test_values = DYNAMIC_TEST_VALUES[param_type][:max_variants]
    
    probe_endpoints = []
    for value in test_values:
        probe_url = sanitized_endpoint.replace('{dynamic}', str(value))
        display_name = f"{sanitized_endpoint} (probe: {value})"
        probe_endpoints.append((probe_url, display_name))
    
    return probe_endpoints

async def stealth_probe_endpoint(session, base_url, endpoint_info, semaphore, timing, header_manager):
    """Стелс версия пробинга endpoints"""
    if isinstance(endpoint_info, tuple):
        probe_url, display_name = endpoint_info
    else:
        probe_url = display_name = endpoint_info
    full_url = urljoin(base_url, probe_url)
    async with semaphore:
        await timing.get_delay()
        headers = header_manager.get_headers(full_url)
        try:
            async with session.get(full_url, headers=headers, timeout=15, ssl=False, allow_redirects=True) as resp:
                status, content = resp.status, await resp.read()
                length, title = len(content), "N/A"
                header_manager.update_session(dict(resp.headers), full_url)
                if 'html' in resp.headers.get('Content-Type', '').lower():
                    try:
                        soup = BeautifulSoup(content.decode('utf-8', errors='ignore'), 'lxml')
                        title_tag = soup.find('title')
                        if title_tag and title_tag.string:
                            title = title_tag.string.strip().replace('\n', ' ').replace('\r', '')
                    except Exception:
                        title = "Parse Error"
                return display_name, status, length, title
        except Exception as e:
            return display_name, 0, 0, f"Request Error: {type(e).__name__}"

def upload_results(file_path):
    print(f"[+] Uploading {file_path} to gofile.io...")
    try:
        result = subprocess.run(["curl", "-s", "-F", f"file=@{file_path}", "https://store1.gofile.io/uploadFile"], capture_output=True, text=True, check=True, errors='ignore')
        data = json.loads(result.stdout)
        if data.get("status") == "ok":
            link = data.get("data", {}).get("downloadPage")
            print(f"[+] Upload successful: {link}")
            return link
    except Exception as e: print(f"[!] An exception occurred during file upload: {e}")
    return None


async def generate_report_and_notify(
    findings_dict: dict, 
    api_keys_dict: dict,
    args: argparse.Namespace, 
    session: aiohttp.ClientSession, 
    timing: HumanLikeTiming, 
    header_manager: SmartHeaders
):
    """Генерирует отчет с эндпоинтами и API-ключами."""
    
    relevant_hosts = set(findings_dict.keys()) | set(api_keys_dict.keys())
    
    if not relevant_hosts:
        print("[+] No new endpoints or API keys found in this scan cycle.")
        return
    
    probe_semaphore = asyncio.Semaphore(args.threads * 2)
    total_new_endpoints = 0
    total_new_keys = 0
    total_probe_tasks = 0
    report_lines = []
    
    print("[+] Generating final report with all findings...")
    
    for host in sorted(list(relevant_hosts)):
        report_lines.append("----------------------------------------")
        report_lines.append(f"Host: {host}")

        # Секция API ключей
        host_keys = api_keys_dict.get(host, [])
        if host_keys:
            total_new_keys += len(host_keys)
            report_lines.append("\n🔥 Found Potential API Keys:")
            # Дедупликация ключей перед выводом
            for key_type, key_value, source in sorted(list(set(host_keys))):
                report_lines.append(f"  - Type: {key_type} | Key: {key_value} | In: {source}")
        
        # Секция эндпоинтов
        endpoints = findings_dict.get(host, [])
        if not endpoints:
            continue
        
        report_lines.append("\n📡 Probing New Endpoints:")
        
        base_url = f"https://{host}"
        _, status, length, title = await stealth_probe_endpoint(session, base_url, "/", probe_semaphore, timing, header_manager)
        if "Request Error" in title:
            print(f"[!] Baseline probe for {host} failed: {title}. Skipping host.", file=sys.stderr)
            report_lines.append(f"  BASELINE: / - PROBE FAILED: {title}")
        else:
            report_lines.append(f"  BASELINE: / - {title} - {status} - {length}")
            
        unique_endpoints = sorted(list(set(endpoints)))
        total_new_endpoints += len(unique_endpoints)
        
        all_probe_tasks = []
        for ep in unique_endpoints:
            probe_variants = generate_probe_endpoints(ep, max_variants=2)
            for probe_info in probe_variants:
                task = asyncio.create_task(stealth_probe_endpoint(session, base_url, probe_info, probe_semaphore, timing, header_manager))
                all_probe_tasks.append(task)
        
        total_probe_tasks += len(all_probe_tasks)
        if not all_probe_tasks: continue

        results = await asyncio.gather(*all_probe_tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                display_name, status, length, title = "Unknown endpoint", 0, 0, f"Error: {type(result).__name__}"
            else:
                display_name, status, length, title = result
            
            report_lines.append(f"  {display_name} - {title} - {status} - {length}")

    if not report_lines: return
    
    report_lines.append("----------------------------------------")
    report_content = "\n".join(report_lines)
    
    header_parts = []
    if total_new_endpoints > 0:
        header_parts.append(f"{total_new_endpoints} new endpoints (probed {total_probe_tasks} variants)")
    if total_new_keys > 0:
        header_parts.append(f"{total_new_keys} potential API keys")

    if not header_parts: return

    header = f"JS-Analyzer found " + " and ".join(header_parts) + "."
    message = f"{header}\n\n```{report_content}```" if len(report_content) < 3500 else ""
    
    if not message:
        tmp_file_path, upload_link_success = None, False
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix="_js_report.txt", encoding='utf-8') as tmp_file:
                tmp_file.write(report_content)
                tmp_file_path = tmp_file.name
            upload_link = await asyncio.get_running_loop().run_in_executor(None, upload_results, tmp_file_path)
            if upload_link:
                message, upload_link_success = f"{header}\nFull report is too large. Download it here: {upload_link}", True
            else:
                message = f"{header}\nFull report is too large. Failed to upload. Report saved locally at: {tmp_file_path}"
        except Exception as e:
            message = f"{header}\nError handling large report file: {e}"
        finally:
            if upload_link_success and tmp_file_path and os.path.exists(tmp_file_path):
                os.remove(tmp_file_path)
                
    await send_notify_alert_async(message, args.notify_provider_config)

async def analyzer_worker_streaming(
    worker_id: int, session: aiohttp.ClientSession, r: redis.Redis,
    semaphore: asyncio.Semaphore, js_queue: asyncio.Queue,
    all_endpoints: dict, all_api_keys: dict,
    lock: asyncio.Lock, pbar_analyze: tqdm, args: argparse.Namespace,
    file_lock: asyncio.Lock, new_endpoints_file,
    timing: HumanLikeTiming, header_manager: SmartHeaders
):
    """
    Финальная версия воркера. Выполняет ДВЕ задачи:
    1. Анализ DIFF: Сравнивает код с предыдущей версией и отправляет diff в AI.
    2. Анализ КОНТЕНТА: Ищет новые эндпоинты и API-ключи (старая логика).
    """
    
    async def analyze_source_code(code_content, source_name, host):
        """Внутренняя функция для анализа любого фрагмента JS-кода"""
        # 1. Поиск API ключей
        keys = extract_api_keys(code_content)
        if keys:
            async with lock:
                for key_type, key_value in keys:
                    all_api_keys[host].append((key_type, key_value, source_name))
        
        # 2. Поиск эндпоинтов
        raw_eps = parser_file(code_content, args)
        sanitized_eps = ultimate_pre_filter_and_sanitize(raw_eps, args)
        pre_filtered_eps = filter_false_positives(sanitized_eps, args)
        endpoints = filter_whitelist_endpoints(pre_filtered_eps, args)
        
        if endpoints:
            redis_key = SEEN_ENDPOINTS_KEY_TPL.format(host=host)
            pipe = r.pipeline()
            for ep in endpoints: pipe.sadd(redis_key, ep)
            results = await pipe.execute()
            newly_added = [ep for i, ep in enumerate(endpoints) if results[i] == 1]
            
            if newly_added:
                async with lock:
                    all_endpoints[host].extend(newly_added)
                if args.debug and new_endpoints_file:
                    async with file_lock:
                        new_endpoints_file.write(f"\n--- New in {source_name} (from {host}) ---\n")
                        for ep in sorted(newly_added): new_endpoints_file.write(f"{ep}\n")

    # Основной цикл воркера
    while True:
        task_item = await js_queue.get()
        if task_item is None:
            js_queue.task_done()
            break
        
        try:
            js_url, source_host, referer_url, inline_content = task_item
            pbar_analyze.set_description(f"Analyzing: {os.path.basename(urlparse(js_url).path)}")
            
            content = inline_content
            is_new_content = True 

            if not content:
                content, is_new_content = await fetch_js_only(
                    session, js_url, semaphore, args, r, referer=referer_url
                )
            
            if not content: 
                continue

            # ==========================================================
            # === ЗАДАЧА 1: АНАЛИЗ DIFF И ОТПРАВКА В AI ===
            # ==========================================================
            try:
                beautified_content_new = jsbeautifier.beautify(content, {"indent_size": 2})
            except Exception as e:
                if args.debug:
                    print(f"[DEBUG] Beautify failed for {js_url}, using raw content. Error: {e}")
                beautified_content_new = content

            current_content_hash = hashlib.sha256(beautified_content_new.encode('utf-8', 'ignore')).hexdigest()
            canonical_url = get_canonical_url(js_url)
            url_hash_key = f"js_diff_hash:{hashlib.md5(canonical_url.encode('utf-8', 'ignore')).hexdigest()}"
            
            last_content_hash_bytes = await r.get(url_hash_key)
            last_content_hash = last_content_hash_bytes.decode() if last_content_hash_bytes else None

            if last_content_hash and last_content_hash != current_content_hash:
                print(f"\n[+] CHANGE DETECTED for: {js_url}")
                old_content_key = f"js_diff_body:{last_content_hash}"
                old_beautified_content_bytes = await r.get(old_content_key)
                
                if old_beautified_content_bytes:
                    old_beautified_content = old_beautified_content_bytes.decode('utf-8', 'ignore')
                    
                    diff = create_beautified_diff(old_beautified_content, beautified_content_new, js_url)

                    # Отправляем в AI для анализа уязвимостей, только если diff не пустой
                    if diff.strip():
                        ai_result = await send_diff_to_ai(session, diff, js_url, args)

                        # Проверяем, что результат есть и в нем найдены сигналы
                        if ai_result and ai_result.get("signals_found"):
                            
                            # Проходим по каждому найденному сигналу
                            for signal in ai_result["signals_found"]:
                                llm_analysis = signal.get("llm_analysis", {})
                                alert_message = llm_analysis.get("alert_message")

                                if alert_message:
                                    # Формируем полное, красивое сообщение для отправки
                                    feature_name = llm_analysis.get("feature_name", "N/A")
                                    test_suggestion = llm_analysis.get("test_area_suggestion", "N/A")
                                    
                                    # Собираем алерт из данных, которые сгенерировал LLM
                                    full_alert = (
                                        f"{alert_message} in {js_url}\n\n"
                                        f"**Feature Name:** {feature_name}\n"
                                        f"**Test Suggestion:** {test_suggestion}"
                                    )
                                    # Отправляем уведомление
                                    await send_notify_alert_async(full_alert, args.notify_provider_config)

            # Обновляем/сохраняем текущую версию в Redis для будущих сравнений, если хэш отличается или его не было
            if last_content_hash != current_content_hash:
                new_content_key = f"js_diff_body:{current_content_hash}"
                pipe = r.pipeline()
                pipe.set(url_hash_key, current_content_hash, ex=86400 * 30)
                pipe.set(new_content_key, beautified_content_new.encode('utf-8', 'ignore'), ex=86400 * 30)
                await pipe.execute()

            # ==========================================================
            # === ЗАДАЧА 2: ПОИСК ЭНДПОИНТОВ И КЛЮЧЕЙ (старая логика) ===
            # ==========================================================
            content_hash_dedup = calculate_content_hash(content)
            if await is_content_processed(r, content_hash_dedup):
                if args.debug:
                    print(f"[DEBUG] Skipping endpoint/key analysis for duplicate content: {js_url}")
                continue
            
            await mark_content_processed(r, content_hash_dedup)

            # Анализируем основной контент
            await analyze_source_code(content, js_url, source_host)

            # Анализ Sourcemap (только для внешних, реально скачанных файлов)
            if not inline_content and is_new_content:
                sourcemap_data = await check_and_extract_sourcemap(session, js_url, content)
                if sourcemap_data:
                    if args.debug:
                        print(f"\n[DEBUG] Found sourcemap for {js_url} with {len(sourcemap_data['sources'])} files.")
                    
                    for source in sourcemap_data['sources']:
                        source_name_in_map = source.get('name', 'unknown_source')
                        source_content = source.get('content')
                        
                        if not source_content:
                            continue

                        source_hash = calculate_content_hash(source_content)
                        if not await is_content_processed(r, source_hash):
                            await mark_content_processed(r, source_hash)
                            await analyze_source_code(
                                source_content, 
                                f"{js_url} -> {source_name_in_map}", 
                                source_host
                            )
                        elif args.debug:
                            print(f"[DEBUG][Worker] Skipping duplicate sourcemap content from: {js_url} -> {source_name_in_map}")

        except Exception as e:
            # Используем locals() чтобы безопасно получить js_url, даже если ошибка была до его присвоения
            url_for_error = locals().get('js_url', 'N/A')
            print(f"\n[!] Worker {worker_id} error processing {url_for_error}: {type(e).__name__}: {e}", file=sys.stderr)
        finally:
            pbar_analyze.update(1)
            js_queue.task_done()

async def analyze_orchestrate(args):
    try:
        r = redis.Redis(host=args.redis_host, port=args.redis_port)
        await r.ping()
        print(f"[+] Connected to Redis for state tracking.")
    except Exception as e:
        sys.exit(f"[!] Redis connection failed: {e}")

    cycle_count = 0
    while True:
        cycle_count += 1
        timing = HumanLikeTiming()
        header_manager = SmartHeaders()
        start_time = time.monotonic()
        base_urls = read_urls_from_file(args.input)
        print(f"\n--- Starting scan cycle {cycle_count} with {len(base_urls)} base URLs at {time.strftime('%Y-%m-%d %H:%M:%S')} ---")

        new_endpoints_file = None
        if args.debug:
            new_endpoints_file = open("new_endpoints.txt", "w", encoding="utf-8")

        js_queue_filename = tempfile.mktemp(suffix="_js_queue.txt")
        found_js_count = 0

        try:
            # === ФАЗА 1: КРАУЛИНГ ===
            print("\n--- Phase 1: Crawling for JS files ---")
            browser_handler = None
            hybrid_fetcher = None
            try:
                BATCH_SIZE = 100
                total_batches = math.ceil(len(base_urls) / BATCH_SIZE)
                
                crawl_semaphore = asyncio.Semaphore(args.threads * 2)
                connector = aiohttp.TCPConnector(limit_per_host=10, ssl=False, enable_cleanup_closed=True)
                
                async with aiohttp.ClientSession(connector=connector) as session:
                    analyzed_urls_in_cycle = set()
                    pbar_crawl = tqdm(total=len(base_urls), desc="Crawling URLs", unit="host", position=0)
                    
                    for batch_num in range(total_batches):
                        start_idx = batch_num * BATCH_SIZE
                        end_idx = min(start_idx + BATCH_SIZE, len(base_urls))
                        batch_urls = base_urls[start_idx:end_idx]
                        
                        print(f"\n[BATCH {batch_num + 1}/{total_batches}] Processing {len(batch_urls)} URLs...")
                        
                        browser_handler, hybrid_fetcher = await init_balanced_hybrid_system(
                            session, r, args.max_browser_concurrency
                        )
                        
                        js_temp_queue = asyncio.Queue(maxsize=2000)
                        
                        async def queue_to_file_writer():
                            nonlocal found_js_count
                            with open(js_queue_filename, 'a', encoding='utf-8') as f_queue:
                                while True:
                                    item = await js_temp_queue.get()
                                    if item is None:
                                        js_temp_queue.task_done()
                                        break
                                    f_queue.write(json.dumps(item) + '\n')
                                    found_js_count += 1
                                    js_temp_queue.task_done()
                        
                        writer_task = asyncio.create_task(queue_to_file_writer())
                        
                        crawler_tasks = [
                            crawl_for_js_links(session, url, crawl_semaphore, js_temp_queue, pbar_crawl,
                                             analyzed_urls_in_cycle, args, timing, header_manager, hybrid_fetcher)
                            for url in batch_urls
                        ]
                        await asyncio.gather(*crawler_tasks)
                        
                        await js_temp_queue.join()
                        await js_temp_queue.put(None)
                        await writer_task
                        
                        await cleanup_balanced_system(browser_handler, hybrid_fetcher)
                        browser_handler = None
                        hybrid_fetcher = None
                        
                        if batch_num < total_batches - 1: await asyncio.sleep(2)
                    
                    pbar_crawl.close()

            finally:
                if hybrid_fetcher and browser_handler:
                    await cleanup_balanced_system(browser_handler, hybrid_fetcher)
                try:
                    import psutil
                    def kill_browsers():
                        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                            proc_cmdline = proc.info.get('cmdline', [])
                            if proc_cmdline and any(k in ' '.join(proc_cmdline).lower() for k in ['chromium', 'playwright']):
                                print(f"[CLEANUP] Force killing browser process PID {proc.info['pid']}")
                                proc.kill()
                    await asyncio.get_running_loop().run_in_executor(None, kill_browsers)
                except (ImportError, Exception): pass
                
                print(f"[+] Discovery phase complete. Found {found_js_count} JS sources (files + inline).")

            # === ФАЗА 2: АНАЛИЗ ===
            if found_js_count > 0:
                print(f"\n--- Phase 2: Analyzing {found_js_count} JS sources ---")
                all_new_endpoints_by_host = defaultdict(list)
                all_new_api_keys_by_host = defaultdict(list)
                lock = asyncio.Lock()
                file_lock = asyncio.Lock()
                
                analysis_semaphore = asyncio.Semaphore(args.threads * 4)
                async with aiohttp.ClientSession() as analysis_session:
                    pbar_analyze = tqdm(total=found_js_count, desc="Analyzing JS", unit="source", position=0)
                    analysis_queue = asyncio.Queue()

                    analyzer_tasks = [
                        asyncio.create_task(
                            analyzer_worker_streaming(
                                worker_id, analysis_session, r, analysis_semaphore, analysis_queue,
                                all_new_endpoints_by_host, all_new_api_keys_by_host,
                                lock, pbar_analyze, args, file_lock, new_endpoints_file,
                                timing, header_manager
                            )
                        ) for worker_id in range(args.threads)
                    ]

                    print(f"[+] Loading {found_js_count} JS sources into analysis queue...")
                    with open(js_queue_filename, 'r', encoding='utf-8') as f:
                        for line in f:
                            if line.strip(): await analysis_queue.put(json.loads(line))
                    
                    for _ in range(args.threads): await analysis_queue.put(None)
                    await asyncio.gather(*analyzer_tasks)
                    pbar_analyze.close()

                print("[+] Analysis phase complete.")
                print("\n--- Final Report Generation ---")
                async with aiohttp.ClientSession() as report_session:
                    await generate_report_and_notify(
                        all_new_endpoints_by_host, all_new_api_keys_by_host,
                        args, report_session, timing, header_manager
                    )
        
        finally:
            if os.path.exists(js_queue_filename): os.remove(js_queue_filename)
            if new_endpoints_file: new_endpoints_file.close()
            await r.aclose()

        end_time = time.monotonic()
        print(f"[+] Scan cycle {cycle_count} finished in {end_time - start_time:.2f} seconds.")

        if not args.continuous:
            print("\n[+] Single run complete. Exiting.")
            break
        print(f"\n[CONTINUOUS MODE] Waiting for {args.delay} seconds before the next run...")
        await asyncio.sleep(args.delay)

def build_parser():
    p = argparse.ArgumentParser(description="Production-ready JS Analyzer with batch processing and content deduplication.")
    p.add_argument("-i", "--input", required=True, help="Input file with base URLs.")
    p.add_argument("--redis-host", default="localhost", help="Redis server host.")
    p.add_argument("--redis-port", type=int, default=6379, help="Redis server port.")
    p.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="Number of JS files to process per batch for checkpoint processing.")
    p.add_argument("--threads", type=int, default=3, help="Number of concurrent analyzer workers per batch.")
    p.add_argument("--continuous", action="store_true", help="Run the script in a continuous loop.")
    p.add_argument("--max-browser-concurrency", type=int, default=1, help="Maximum simultaneous browser fetches (1-2 recommended for stability).")
    p.add_argument("--delay", type=int, default=1, help="Delay in seconds between scans in continuous mode.")
    p.add_argument("-pc", "--notify-provider-config", help="Path to the notify provider-config file (optional).")
    p.add_argument("--debug", action="store_true", help="Enable verbose debug logging and file output.")
    return p

def main():
    args = build_parser().parse_args()
    try: import lxml
    except ImportError: print("[!] 'lxml' not found. For better performance, run: pip install lxml")
    try: asyncio.run(analyze_orchestrate(args))
    except KeyboardInterrupt: print("\n[!] Analysis interrupted by user.", file=sys.stderr)

if __name__ == "__main__":

    main()

