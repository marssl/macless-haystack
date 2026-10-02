import asyncio
import base64
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import AsyncMock, patch

from aiohttp import ClientSession, web
from aiohttp.test_utils import TestServer

# Loading only the request handlers must never initialize Apple credentials.
sys.modules.setdefault('mh_config', types.ModuleType('mh_config'))
register=types.ModuleType('register')
register.apple_cryptography=types.SimpleNamespace()
register.pypush_gsa_icloud=types.SimpleNamespace()
sys.modules.setdefault('register',register)
spec=importlib.util.spec_from_file_location('query_candidate',Path(__file__).parents[1]/'mh_endpoint_async.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

NOW=1780000000
def payload(at=NOW):return base64.b64encode((at-978307200).to_bytes(4,'big')+b'example').decode()
def body(key='key0'):
    return {'acsnLocations':{'statusCode':'200','locationPayload':[{'id':key,'locationInfo':[payload()]}]}}

class Response:
    def __init__(self,status=200,value=None,delay=0,headers=None):
        self.status,self.value,self.delay,self.headers=status,value,delay,headers or {}
    async def __aenter__(self):
        if self.delay:await asyncio.sleep(self.delay)
        return self
    async def __aexit__(self,*_):pass
    async def text(self):return self.value if isinstance(self.value,str) else json.dumps(self.value)

class Session:
    def __init__(self,responses):self.responses=responses;self.calls=0
    def post(self,*_,**kwargs):
        self.calls+=1
        key=kwargs['json']['fetch'][0]['primaryIds'][0]
        values=self.responses[key]
        return values.pop(0) if len(values)>1 else values[0]

class Tests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):m.sem=asyncio.Semaphore(4)
    async def run_query(self,session,ids=None,**kwargs):
        ids=ids or ['key0']
        return await m.collect_reports(session,ids,None,{},NOW-100,NOW+10,**kwargs)

    async def test_503_recovers_without_duplicate_reports(self):
        s=Session({'key0':[Response(503,{}),Response(503,{}),Response(200,body())]})
        with patch.object(m.asyncio,'sleep',new=AsyncMock()):r=await self.run_query(s)
        self.assertEqual(len(r['results']),1);self.assertEqual(r['query']['status'],'complete')
        self.assertEqual(r['query']['retries'],2)
        self.assertEqual(r['query']['batch_details'][0]['attempt_errors'],['http_503','http_503'])

    async def test_success_survives_failed_batch_and_device_coverage(self):
        ids=['key'+str(i) for i in range(101)]
        s=Session({'key0':[Response(200,body())],'key100':[Response(503,{})]})
        with patch.object(m.asyncio,'sleep',new=AsyncMock()):
            r=await self.run_query(s,ids,devices={'a':ids[:100],'b':ids[100:],'c':[ids[0],ids[100]]})
        self.assertEqual(len(r['results']),1);self.assertEqual(r['query']['status'],'partial')
        self.assertEqual({k:v['status'] for k,v in r['query']['devices'].items()},{'a':'complete','b':'failed','c':'partial'})

    async def test_authentication_not_retried_or_reported_as_empty_success(self):
        s=Session({'key0':[Response(401,{})]});r=await self.run_query(s)
        self.assertEqual(s.calls,1);self.assertEqual(r['query']['status'],'failed')
        self.assertEqual(r['query']['batch_details'][0]['error'],'authentication')

    async def test_empty_invalid_json_and_legitimate_empty_are_distinct(self):
        for first,error in [('', 'empty_response'),('{bad', 'invalid_json')]:
            s=Session({'key0':[Response(200,first),Response(200,{'acsnLocations':{'statusCode':'200','locationPayload':[]}})]})
            with patch.object(m.asyncio,'sleep',new=AsyncMock()):r=await self.run_query(s)
            self.assertEqual(r['query']['status'],'complete');self.assertEqual(r['results'],[])
            self.assertEqual(r['query']['batch_details'][0]['attempt_errors'],[error])

    async def test_nonretryable_http_error(self):
        s=Session({'key0':[Response(400,{})]});r=await self.run_query(s)
        self.assertEqual(s.calls,1);self.assertEqual(r['query']['status'],'failed')

    async def test_long_retry_after_is_not_ignored(self):
        s=Session({'key0':[Response(429,{},headers={'Retry-After':'120'})]})
        r=await self.run_query(s)
        self.assertEqual(s.calls,1);self.assertEqual(r['query']['status'],'failed')

    async def test_round_deadline_keeps_completed_data(self):
        ids=['key'+str(i) for i in range(101)]
        s=Session({'key0':[Response(200,body())],'key100':[Response(200,body('key100'),delay=1)]})
        r=await self.run_query(s,ids,round_timeout=.02)
        self.assertEqual(len(r['results']),1);self.assertEqual(r['query']['status'],'partial')
        self.assertEqual(r['query']['batch_details'][1]['error'],'round_timeout')

    async def test_layouts_preserve_keys_and_requested_range(self):
        a=m.make_request(['a','b'],10,20,'grouped');b=m.make_request(['a','b'],10,20,'individual')
        self.assertEqual(a['fetch'][0]['primaryIds'],['a','b'])
        self.assertEqual([item['primaryIds'] for item in b['fetch']],[['a'],['b']])
        self.assertTrue(all(item['startDate']==10000 and item['endDate']==20000 for item in b['fetch']))

    async def test_invalid_report_is_rejected(self):
        with self.assertRaises(m.BatchError):m.parse_reports(body('unexpected'),{'key0'})
        bad=body();bad['acsnLocations']['locationPayload'][0]['locationInfo']=['bad-base64']
        with self.assertRaises(m.BatchError):m.parse_reports(bad,{'key0'})

    async def test_real_http_retries_and_partial_results(self):
        calls={}
        async def upstream(request):
            data=await request.json();key=data['fetch'][0]['primaryIds'][0]
            calls[key]=calls.get(key,0)+1
            if key=='key100' or calls[key]==1:return web.Response(status=503)
            return web.json_response(body(key))
        app=web.Application();app.router.add_post('/',upstream)
        async with TestServer(app) as server, ClientSession() as session:
            ids=['key'+str(i) for i in range(101)]
            r=await self.run_query(session,ids,upstream_url=str(server.make_url('/')))
        self.assertEqual(r['query']['status'],'partial');self.assertEqual(len(r['results']),1)
        self.assertEqual(calls,{'key0':2,'key100':3})

    async def test_handler_marks_partial_and_all_failed_http_status(self):
        fake_result={'results':[],'query':{'status':'partial','retries':0,'batch_details':[]}}
        class Request:
            async def json(self):return {'ids':['key0']}
        with patch.object(m,'authenticate',return_value=True),patch.object(m,'getAuth',return_value=None),patch.object(m.pypush_gsa_icloud,'generate_anisette_headers',return_value={},create=True),patch.object(m,'collect_reports',new=AsyncMock(return_value=fake_result)):
            r=await m.handle_post(Request());self.assertEqual(r.status,200)
            self.assertEqual(json.loads(r.text)['query']['status'],'partial')
            fake_result['query']['status']='failed'
            r=await m.handle_post(Request());self.assertEqual(r.status,502)
            self.assertIn('error',json.loads(r.text))

if __name__=='__main__':unittest.main()
