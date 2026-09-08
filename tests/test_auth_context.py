"""Offline request-contract tests. These do not claim a successful Apple login."""
import plistlib
import unittest
from unittest.mock import Mock, patch

from endpoint.register import pypush_gsa_icloud as auth


def response(payload=None, status=200):
    result = Mock(status_code=status, ok=200 <= status < 300,
                  headers={'Content-Type': 'text/x-xml-plist'})
    result.content = plistlib.dumps(payload or {'ec': 0})
    result.__enter__ = Mock(return_value=result)
    result.__exit__ = Mock(return_value=False)
    return result


class AuthContextTests(unittest.TestCase):
    def test_init_503_then_success_reuses_session(self):
        session = Mock()
        session.post.side_effect = [response(status=503), response({'Response': {'Status': {'ec': 0}}})]
        with patch.object(auth, 'generate_anisette_headers', return_value={}), patch.object(auth.time, 'sleep') as sleep:
            result = auth.gsa_authenticated_request({'o': 'init', 'A2k': b'A'}, session)
        self.assertEqual(result['Status']['ec'], 0)
        self.assertEqual(session.post.call_count, 2)
        sleep.assert_called_once_with(2)
        self.assertEqual(session.post.call_args_list[0], session.post.call_args_list[1])

    def test_init_retries_are_bounded(self):
        session = Mock()
        session.post.return_value = response(status=503)
        with patch.object(auth, 'generate_anisette_headers', return_value={}), patch.object(auth.time, 'sleep') as sleep:
            with self.assertRaisesRegex(auth.AppleAuthError, '503'):
                auth.gsa_authenticated_request({'o': 'init'}, session)
        self.assertEqual(session.post.call_count, 3)
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [2, 5])

    def test_password_proof_and_unauthorized_are_not_retried(self):
        for operation, status in [('complete', 503), ('init', 401), ('init', 429)]:
            with self.subTest(operation=operation, status=status):
                session = Mock()
                session.post.return_value = response(status=status)
                with patch.object(auth, 'generate_anisette_headers', return_value={}), patch.object(auth.time, 'sleep') as sleep:
                    with self.assertRaises(auth.AppleAuthError):
                        auth.gsa_authenticated_request({'o': operation}, session)
                self.assertEqual(session.post.call_count, 1)
                sleep.assert_not_called()

    def test_server_cooldown_is_respected(self):
        session = Mock()
        failed = response(status=503)
        failed.headers['Retry-After'] = '120'
        session.post.return_value = failed
        with patch.object(auth, 'generate_anisette_headers', return_value={}), patch.object(auth.time, 'sleep') as sleep:
            with self.assertRaisesRegex(auth.AppleAuthError, 'cooldown'):
                auth.gsa_authenticated_request({'o': 'init'}, session)
        self.assertEqual(session.post.call_count, 1)
        sleep.assert_not_called()

    def test_case_variants_do_not_replace_server_identity(self):
        data = {'X-Apple-I-MD': 'otp', 'X-Apple-I-MD-M': 'machine',
                'x-mme-device-id': 'server-device', 'x-apple-i-md-lu': 'server-user',
                'X-MMe-Client-Info': 'server-client'}
        r = response()
        r.json.return_value = data
        with patch.object(auth.requests, 'get', return_value=r):
            headers = auth.generate_anisette_headers()
            self.assertEqual(headers['X-Mme-Device-Id'], 'server-device')
            self.assertEqual(headers['X-Apple-I-MD-LU'], 'server-user')
            self.assertEqual(len(headers), len({k.lower() for k in headers}))

    def test_gsa_and_2fa_use_same_client_description(self):
        ani = auth.requests.structures.CaseInsensitiveDict({
            'X-MMe-Client-Info': 'server-client', 'X-Mme-Device-Id': 'device'})
        session = Mock()
        session.post.return_value = response({'Response': {'Status': {'ec': 0}}})
        with patch.object(auth, 'generate_anisette_headers', return_value=ani):
            auth.gsa_authenticated_request({'o': 'init'}, session)
            request = session.post.call_args.kwargs
            self.assertEqual(request['headers']['X-MMe-Client-Info'], 'server-client')
            cpd = plistlib.loads(request['data'])['Request']['cpd']
            self.assertNotIn('X-MMe-Client-Info', cpd)
            self.assertEqual(cpd['X-Mme-Device-Id'], 'device')
            self.assertEqual(auth._identity_headers('dsid', 'token')['X-Mme-Client-Info'], 'server-client')

    def test_trusted_headers_and_business_success(self):
        session = Mock()
        session.get.side_effect = [response(), response({'ec': 0})]
        with patch.object(auth, 'generate_anisette_headers', return_value={}), patch.object(auth, 'getpass', return_value='123456'):
            auth.trusted_second_factor('dsid', 'token', session)
        for call in session.get.call_args_list:
            self.assertEqual(call.kwargs['headers']['Accept'], 'text/x-xml-plist')
            self.assertEqual(call.kwargs['headers']['Content-Type'], 'text/x-xml-plist')

    def test_http_200_with_invalid_code_is_not_success(self):
        session = Mock()
        session.get.side_effect = [response(), response({'ec': -21669})]
        with patch.object(auth, 'generate_anisette_headers', return_value={}), patch.object(auth, 'getpass', return_value='123456'):
            with self.assertRaisesRegex(auth.AppleAuthError, '-21669'):
                auth.trusted_second_factor('dsid', 'token', session)

    def test_401_does_not_prompt_or_retry(self):
        session = Mock()
        session.get.return_value = response(status=401)
        with patch.object(auth, 'generate_anisette_headers', return_value={}), patch.object(auth, 'getpass') as prompt:
            with self.assertRaisesRegex(auth.AppleAuthError, 'challenge: HTTP 401'):
                auth.trusted_second_factor('dsid', 'token', session)
            prompt.assert_not_called()
        self.assertEqual(session.get.call_count, 1)

    def test_apple_rejection_preserved(self):
        with self.assertRaisesRegex(auth.AppleAuthError, '-80002'):
            auth._raise_for_apple_status({'Status': {'ec': -80002, 'em': 'Username is invalid.'}}, 'init')


if __name__ == '__main__':
    unittest.main()
