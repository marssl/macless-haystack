import base64
import json
import os
import logging
import ssl
import sys
import time
import random
import uuid
import math
from email.utils import parsedate_to_datetime
from collections import Counter
from collections import OrderedDict
from datetime import datetime, timezone

from aiohttp import web, BasicAuth, ClientSession, ClientTimeout
from aiohttp import ClientConnectionError, ClientPayloadError
import asyncio

import requests

import mh_config
from register import apple_cryptography, pypush_gsa_icloud

logger = logging.getLogger()
logging.basicConfig(level=logging.DEBUG)

sem = asyncio.Semaphore(4)  # 最多4个并发请求，防止被封IP
query_metrics = Counter()
last_query = {}


class BatchError(Exception):
    def __init__(self, code, retryable=False, delay=None):
        self.code, self.retryable, self.delay = code, retryable, delay


def make_request(ids, start, end, layout='grouped'):
    groups = [ids] if layout == 'grouped' else [[key] for key in ids]
    return {'clientContext': {'clientBundleIdentifier': 'com.apple.icloud.searchpartyuseragent',
                             'policy': 'foregroundClient'},
            'fetch': [{'ownedDeviceIds': [], 'keyType': 1, 'startDate': start * 1000,
                       'startDateSecondary': start * 1000, 'endDate': end * 1000,
                       'primaryIds': group, 'secondaryIds': []} for group in groups]}


def parse_reports(raw, allowed_ids):
    if not isinstance(raw, dict):
        raise BatchError('invalid_response', True)
    locations = raw.get('acsnLocations')
    if not isinstance(locations, dict):
        raise BatchError('invalid_response', True)
    code = str(locations.get('statusCode'))
    if code != '200':
        raise BatchError('authentication' if code in ('401', '403') else 'upstream_protocol', code not in ('401', '403'))
    groups = locations.get('locationPayload', [])
    if not isinstance(groups, list):
        raise BatchError('invalid_response', True)
    results = []
    for group in groups:
        if not isinstance(group, dict) or group.get('id') not in allowed_ids or not isinstance(group.get('locationInfo', []), list):
            raise BatchError('invalid_response', True)
        for payload in group.get('locationInfo', []):
            try:
                data = base64.b64decode(payload, validate=True)
            except (ValueError, TypeError):
                raise BatchError('invalid_payload', True) from None
            if len(data) < 4:
                raise BatchError('invalid_payload', True)
            results.append({'id': group['id'], 'payload': payload})
    return results

def authenticate(self):
    endpoint_user = mh_config.getEndpointUser()
    endpoint_pass = mh_config.getEndpointPass()
    if (endpoint_user is None or endpoint_user == "") and (endpoint_pass is None or endpoint_pass == ""):
        return True
    auth_header = self.headers.get('authorization')
    if auth_header:
        auth_type, auth_encoded = auth_header.split(None, 1)
        if auth_type.lower() == 'basic':
            auth_decoded = base64.b64decode(auth_encoded).decode('utf-8')
            username, password = auth_decoded.split(':', 1)
            if username == endpoint_user and password == endpoint_pass:
                return True
    return False

def getAuth(regenerate=False, second_factor='sms'):
    if os.path.exists(mh_config.getConfigFile()) and not regenerate:
        with open(mh_config.getConfigFile(), "r") as f:
            j = json.load(f)
    else:
        mobileme = pypush_gsa_icloud.icloud_login_mobileme(username=mh_config.USER, password=mh_config.PASS)
        logger.debug('Mobileme result: ' + mobileme)
        j = {'dsid': mobileme['dsid'], 'searchPartyToken': mobileme['delegates']
             ['com.apple.mobileme']['service-data']['tokens']['searchPartyToken']}
        with open(mh_config.getConfigFile(), "w") as f:
            json.dump(j, f)
    return BasicAuth(j['dsid'], j['searchPartyToken'])

async def handle_options(request):
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'X-Requested-With, Content-Type, Authorization',
        'Access-Control-Allow-Private-Network': 'true',
    }
    return web.Response(status=200, headers=headers)

async def handle_get(request):
    if not authenticate(request):
        headers = {
            'WWW-Authenticate': 'Basic realm="Auth Realm"'
        }
        return web.Response(status=401, headers=headers)
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Content-type': 'text/plain'
    }
    return web.Response(text="Nothing to see here", headers=headers)


async def fetch(session, url, data, auth, headers, ids, request_timeout=8, max_attempts=3):
    started = time.monotonic()
    outcome = {'status': 'failed', 'attempts': 0, 'reports': [], 'error': None, 'attempt_errors': []}
    try:
        for attempt in range(1, max_attempts + 1):
            outcome['attempts'] = attempt
            try:
                async with sem:
                    async with session.post(url, auth=auth, headers=headers, json=data,
                                            timeout=ClientTimeout(total=request_timeout, connect=4)) as resp:
                        if resp.status in (401, 403):
                            raise BatchError('authentication')
                        if resp.status != 200:
                            retryable = resp.status in (408, 429, 500, 502, 503, 504)
                            try:
                                value = resp.headers.get('Retry-After', '')
                                try:delay = float(value)
                                except ValueError:delay = parsedate_to_datetime(value).timestamp() - time.time()
                                if not math.isfinite(delay):raise ValueError('invalid delay')
                                delay = max(0,delay)
                                if delay > 4:retryable=False  # Defer to the next scheduled poll, never retry early.
                            except (ValueError, TypeError, OverflowError):delay = None
                            raise BatchError('http_' + str(resp.status), retryable, delay)
                        text = await resp.text()
                        if not text.strip():
                            raise BatchError('empty_response', True)
                        try:
                            raw = json.loads(text)
                        except json.JSONDecodeError:
                            raise BatchError('invalid_json', True) from None
                        outcome['reports'] = parse_reports(raw, set(ids))
                        outcome.update(status='complete', error=None)
                        return outcome
            except (asyncio.TimeoutError, ClientConnectionError, ClientPayloadError) as exc:
                failure = BatchError('timeout' if isinstance(exc, asyncio.TimeoutError) else 'connection', True)
            except BatchError as exc:
                failure = exc
            outcome['error'] = failure.code
            outcome['attempt_errors'].append(failure.code)
            if not failure.retryable or attempt == max_attempts:
                return outcome
            await asyncio.sleep(failure.delay if failure.delay is not None else 2 ** (attempt - 1) + random.uniform(0, .25))
    except asyncio.CancelledError:
        outcome['error'] = 'round_timeout'
        outcome['attempt_errors'].append('round_timeout')
        return outcome
    finally:
        outcome['elapsed_ms'] = round((time.monotonic() - started) * 1000)


async def collect_reports(session, ids, auth, headers, start, end, devices=None,
                          layout='grouped', round_timeout=40, request_timeout=8,
                          upstream_url='https://gateway.icloud.com/findmyservice/v2/fetch'):
    started = time.monotonic()
    groups = [ids[i:i+100] for i in range(0, len(ids), 100)]
    tasks = [asyncio.create_task(fetch(session, upstream_url,
                                    make_request(group, start, end, layout), auth, headers, group,
                                    request_timeout=request_timeout)) for group in groups]
    if tasks:
        try:
            _, pending = await asyncio.wait(tasks, timeout=round_timeout)
            for task in pending:
                task.cancel()
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            for task in tasks: task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
    else:
        outcomes = []
    batches, results, successful_ids = [], {}, set()
    for index, (group, outcome) in enumerate(zip(groups, outcomes)):
        if isinstance(outcome, BaseException):
            outcome = {'status':'failed', 'attempts':0, 'reports':[], 'error':'internal_batch_error', 'elapsed_ms':0}
        reports = outcome.pop('reports')
        if outcome['status'] == 'complete':
            successful_ids.update(group)
            for report in reports:
                timestamp = int.from_bytes(base64.b64decode(report['payload'])[:4], 'big') + 978307200
                if start <= timestamp <= end:
                    results[(timestamp, report['id'], report['payload'])] = report
        batches.append({'index':index, 'keys':len(group), 'reports':len(reports), **outcome})
    complete = sum(b['status'] == 'complete' for b in batches)
    status = 'complete' if complete == len(groups) else ('partial' if complete else 'failed')
    device_status = {}
    for device, keys in (devices or {}).items():
        succeeded = sum(key in successful_ids for key in keys)
        device_status[device] = {'status':'complete' if succeeded == len(keys) else ('partial' if succeeded else 'failed'),
                                 'keys':len(keys), 'successful_keys':succeeded}
    ordered = [results[k] for k in sorted(results, reverse=True)]
    summary = {'id':uuid.uuid4().hex, 'status':status, 'layout':layout, 'batches':len(groups),
               'successful_batches':complete, 'failed_batches':len(groups)-complete,
               'retries':sum(max(0,b['attempts']-1) for b in batches), 'reports':len(ordered),
               'elapsed_ms':round((time.monotonic()-started)*1000),
               'latest_report_age_seconds':end-max((k[0] for k in results),default=end) if results else None,
               'batch_details':batches, 'devices':device_status}
    return {'results':ordered, 'query':summary}


async def handle_status(request):
    if not authenticate(request):
        return web.json_response({'error':'unauthorized'},status=401)
    return web.json_response({'counters':dict(query_metrics), 'last_query':last_query},headers={'Cache-Control':'no-store'})
        
async def handle_post(request):
    global last_query
    if not authenticate(request):
        headers = {
            'WWW-Authenticate': 'Basic realm="Auth Realm"'
        }
        return web.Response(status=401, headers=headers)
    validated = False
    try:
        body = await request.json()
        if not isinstance(body, dict) or not isinstance(body.get('ids'),list):
            raise ValueError('invalid request')
        ids = list(dict.fromkeys(body['ids']))
        if len(ids)>10000 or any(not isinstance(key,str) or not key or len(key)>128 for key in ids):
            raise ValueError('invalid keys')
        days = int(body.get('days',7))
        layout = body.get('layout','grouped')
        if not 1 <= days <= 7 or layout not in ('grouped','individual'):
            raise ValueError('invalid range or layout')
        devices = body.get('devices',{})
        if not isinstance(devices,dict) or len(devices)>100:
            raise ValueError('invalid devices')
        if any(not isinstance(device,str) or len(device)>128 or not isinstance(keys,list)
               or not keys or any(key not in ids for key in keys) for device,keys in devices.items()):
            raise ValueError('invalid device keys')
        devices = {device:list(dict.fromkeys(keys)) for device,keys in devices.items()}
        validated = True
        unixEpoch = int(time.time())
        startdate = unixEpoch - 86400 * days
        auth = getAuth(regenerate=False, second_factor='sms')
        headers = pypush_gsa_icloud.generate_anisette_headers()
        async with ClientSession(timeout=ClientTimeout(total=40)) as session:
            result = await collect_reports(session, ids, auth, headers, startdate, unixEpoch, devices, layout)
        last_query = result['query']
        query_metrics['queries'] += 1
        query_metrics[last_query['status']] += 1
        query_metrics['retries'] += last_query['retries']
        for batch in last_query['batch_details']:
            for error in batch.get('attempt_errors',[]): query_metrics[error] += 1
        logger.info('report_query %s',json.dumps({k:v for k,v in last_query.items() if k not in ('devices','batch_details')}))
        if last_query['status']=='failed':
            result['error']='Apple report query failed; see query batch_details'
        return web.json_response(result, status=502 if last_query['status']=='failed' else 200,
                                 headers={'Access-Control-Allow-Origin':'*','Cache-Control':'no-store'})
    except (ValueError,TypeError,KeyError):
        return web.json_response({'error':'query_setup_failed' if validated else 'invalid_request'},status=502 if validated else 400)
    except Exception:
        logger.error('Report query setup failed')
        return web.json_response({'error': 'Apple report request failed'}, status=502)

def check_if_anisette_is_reachable(max_retries=3, retry_delay=10):
    server_url = mh_config.getAnisetteServer()
    logging.info(f'Checking if Anisette {server_url} is reachable')
    for attempt in range(max_retries):
        try:
            response = requests.get(server_url, timeout=5)
            response.raise_for_status()
            return
        except (requests.RequestException, requests.HTTPError) as e:
            logger.error(f"Attempt {attempt + 1} failed: {str(e)}")
            if attempt < max_retries - 1:
                logger.error(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
    logger.error(f"Max retries reached. Program will exit. Make sure your Anisette is reachable and start again with 'docker start -ai macless-haystack'")
    sys.exit()

if __name__ == "__main__":
    check_if_anisette_is_reachable()
    logging.info(f'Searching for token at ' + mh_config.getConfigFile())
    if not os.path.exists(mh_config.getConfigFile()):
        logging.info(f'No auth-token found.')
        apple_cryptography.registerDevice()

    app = web.Application()
    app.router.add_options('/', handle_options)
    app.router.add_get('/', handle_get)
    app.router.add_get('/status', handle_status)
    app.router.add_post('/', handle_post)
    
    address = mh_config.getBindingAddress() + ":" + str(mh_config.getPort())
    hasCert = os.path.isfile(mh_config.getCertFile())
    if hasCert:
        logger.info("Certificate file " + mh_config.getCertFile() +
                    " exists, so using SSL")
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=mh_config.getCertFile(
        ), keyfile=mh_config.getKeyFile() if os.path.isfile(mh_config.getKeyFile()) else None)

        logger.info("serving at " + address + " over HTTPS")
    else:
        logger.info("Certificate file " + mh_config.getCertFile() +
                    " not found, so not using SSL")
        logger.info("serving at " + address + " over HTTP")
    
    user = mh_config.getEndpointUser()
    passw = mh_config.getEndpointPass()
    if (user is None or user == "") and (passw is None or passw == ""):
        logger.warning("Endpoint is not protected by authentication")
    else:
        logger.info("Endpoint is protected by authentication")

    web.run_app(app, host=mh_config.getBindingAddress(), port=mh_config.getPort(), ssl_context=ssl_context if hasCert else None)
