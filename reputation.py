import asyncio
import ipaddress
import json
import re
import time
from collections import OrderedDict
from time import monotonic
from urllib.parse import quote, urlencode

from tornado.httpclient import AsyncHTTPClient, HTTPClientError, HTTPRequest

PROVIDERS = {
    'yandex': 'Яндекс',
    'cloudflare': 'Cloudflare Radar · провайдер',
    'proxycheck': 'ProxyCheck',
    'ipqs': 'IPQualityScore',
    'ipapi': 'ipapi.is',
}
CACHE_TTL_SECONDS = 24 * 60 * 60
CACHE_MAX_SIZE = 1024
CACHE = OrderedDict()
PENDING = {}
LOOKUP_MAX_IPS = 16


def parse_lookup_target(value):
    value = value.strip()
    if not value or len(value) > 253 or '%' in value:
        raise ValueError('Введите IP-адрес или домен без URL, порта и пути')
    try:
        return str(ipaddress.ip_address(value)), True
    except ValueError:
        pass
    try:
        domain = value.removesuffix('.').encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise ValueError('Некорректное доменное имя') from None
    if (
        len(domain) > 253
        or re.fullmatch(r'[0-9.]+', domain)
        or not all(
            re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
            for label in domain.split('.')
        )
    ):
        raise ValueError('Введите IP-адрес или домен без URL, порта и пути')
    return domain, False


async def cached_check(provider, ip, key, check):
    cache_key = (provider, ip, key)
    cached = CACHE.get(cache_key)
    if cached and monotonic() - cached[0] < CACHE_TTL_SECONDS:
        CACHE.move_to_end(cache_key)
        return {**cached[1], 'cached': True}
    CACHE.pop(cache_key, None)

    async def load():
        try:
            result = await check()
        except Exception:
            result = {'status': 'error', 'error': 'Сервис недоступен'}
        result.setdefault('status', 'error')
        result = {**result, 'checked_at': int(time.time()), 'cached': False}
        if result['status'] == 'ok':
            CACHE[cache_key] = (monotonic(), result)
            CACHE.move_to_end(cache_key)
            while len(CACHE) > CACHE_MAX_SIZE:
                CACHE.popitem(last=False)
        return result

    task = PENDING.get(cache_key)
    if task is None:
        task = asyncio.create_task(load())
        PENDING[cache_key] = task
        task.add_done_callback(lambda _: PENDING.pop(cache_key, None))
    return await asyncio.shield(task)


def parse_result(provider, ip, data):
    if not isinstance(data, dict):
        raise ValueError('Некорректный ответ сервиса')
    if provider == 'cloudflare':
        if data.get('success') is not True:
            raise ValueError('Сервис отклонил запрос: проверьте токен и права')
        item = data['result']['ip']
        if ipaddress.ip_address(item['ip']) != ipaddress.ip_address(ip):
            raise ValueError('IP в ответе сервиса не совпал')
        fields = {
            'Провайдер': item.get('asnOrgName') or item.get('asnName'),
            'ASN': item.get('asn'),
        }
    elif provider == 'proxycheck':
        if data.get('status') not in ('ok', 'warning'):
            raise ValueError('Сервис отклонил запрос: проверьте ключ и квоту')
        item = data[ip]
        fields = {
            'Прокси/VPN': item.get('proxy'),
            'Тип': item.get('type'),
            'Риск (0–100)': item.get('risk'),
        }
    elif provider == 'ipqs':
        if data.get('success') is not True:
            raise ValueError('Сервис отклонил запрос: проверьте ключ и квоту')
        fields = {
            'VPN': data.get('vpn'),
            'Прокси': data.get('proxy'),
            'Tor': data.get('tor'),
            'Fraud score (0–100)': data.get('fraud_score'),
            'Недавние злоупотребления': data.get('recent_abuse'),
        }
    elif provider == 'ipapi':
        if data.get('error') or ipaddress.ip_address(
            data.get('ip', '')
        ) != ipaddress.ip_address(ip):
            raise ValueError('Некорректный ответ сервиса или ключ')
        fields = {
            'VPN': data.get('is_vpn'),
            'Прокси': data.get('is_proxy'),
            'Tor': data.get('is_tor'),
            'Дата-центр': data.get('is_datacenter'),
            'Злоупотребления': data.get('is_abuser'),
        }
    else:
        raise ValueError('Неизвестный сервис репутации')
    if not any(value is not None for value in fields.values()):
        raise ValueError('Сервис не вернул данные о репутации')
    return {'status': 'ok', 'fields': fields}


async def check_service(provider, ip, key):
    headers = {'Accept': 'application/json'}
    method, body = 'GET', None
    if provider == 'cloudflare':
        url = 'https://api.cloudflare.com/client/v4/radar/entities/ip?' + urlencode(
            {'ip': ip}
        )
        headers['Authorization'] = 'Bearer ' + key
    elif provider == 'proxycheck':
        url = (
            'https://proxycheck.io/v2/'
            + quote(ip, safe='')
            + '?'
            + urlencode({'key': key, 'vpn': 1, 'risk': 1})
        )
    elif provider == 'ipqs':
        url = 'https://www.ipqualityscore.com/api/json/ip/'
        headers['Content-Type'] = 'application/json'
        method, body = 'POST', json.dumps({'ip': ip, 'key': key})
    elif provider == 'ipapi':
        url = 'https://api.ipapi.is/'
        headers['Content-Type'] = 'application/json'
        method, body = 'POST', json.dumps({'q': ip, 'key': key})
    else:
        raise ValueError('Неизвестный сервис репутации')
    try:
        response = await AsyncHTTPClient().fetch(
            HTTPRequest(
                url,
                method=method,
                body=body,
                headers=headers,
                connect_timeout=5,
                request_timeout=15,
                follow_redirects=False,
            )
        )
        return parse_result(provider, ip, json.loads(response.body))
    except HTTPClientError as error:
        return {
            'status': 'error',
            'error': f'Ошибка HTTP {error.code}: проверьте доступность, ключ и квоту',
        }
    except Exception:
        # Provider URLs and exception messages can contain API keys.
        return {'status': 'error', 'error': 'Некорректный ответ сервиса'}


async def get_reputation(ip, keys, yandex_check=None):
    async def one(provider):
        key = keys.get(provider, '')
        if provider != 'yandex' and not key:
            return {
                'provider': provider,
                'name': PROVIDERS[provider],
                'status': 'unconfigured',
                'error': 'API-ключ не настроен',
            }

        async def check():
            return (
                await yandex_check()
                if provider == 'yandex'
                else await check_service(provider, ip, key)
            )

        result = await cached_check(provider, ip, key, check)
        return {'provider': provider, 'name': PROVIDERS[provider], **result}

    return await asyncio.gather(
        *(
            one(provider)
            for provider in PROVIDERS
            if provider != 'yandex' or yandex_check is not None
        )
    )
