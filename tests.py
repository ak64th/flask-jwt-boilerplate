import unittest

import simplejson as json

from cas.app import app
from db import users


class AuthTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.testing = True

    def setUp(self):
        self.client = app.test_client()

    def post_json(self, url, data):
        data = json.dumps(data)
        resp = self.client.post(url, headers={'Content-Type': 'application/json'}, data=data)
        return resp, json.loads(resp.data)

    def test_homepage(self):
        resp = self.client.get('/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data, 'OK')

    def test_jwt_required_decorator_with_valid_request_current_identity(self):
        user = users[0]
        data = {
            'credential': {
                'username': user.username,
                'password': user.password
            },
            'type': 'username'
        }
        resp, resp_data = self.post_json('/auth/login/', data)
        token = resp_data['access_token']
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(token)
        resp = self.client.get('/auth/info/',
                               headers={'authorization': 'Bearer ' + token})
        resp_data = json.loads(resp.data)
        self.assertEqual(resp_data['username'], user.username)
        self.assertEqual(resp_data['id'], user.id)


if __name__ == '__main__':
    unittest.main()
