#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
from google.appengine.api import urlfetch


import time
import uuid
import hmac
import hashlib
import re
import logging
import urllib
import json
from urllib import quote, urlencode

app_key = 'QNDgnEVG5ZNGdrO2pBzfAw'
app_secret = 'P0CiG5quXW9VwfynUhuDtVjfBkgCKlRtnncR0mNlVo'


def get_request_token():
    url = 'https://api.twitter.com/oauth/request_token'

    params = [
        ('oauth_consumer_key', app_key),
        ('oauth_nonce', uuid.uuid4().hex),
        ('oauth_signature_method', 'HMAC-SHA1'),
        ('oauth_timestamp', int(time.time())),
        ('oauth_version', '1.0'),
        ]

    params.sort()

    p = 'POST&%s&%s' % (quote(url, safe=''), quote(urlencode(params)))
    signature = hmac.new(app_secret + '&', p, hashlib.sha1).digest().encode('base64').rstrip()

    params.append(('oauth_signature', quote(signature)))

    h = ', '.join(['%s="%s"' % (k, v) for (k, v) in params])

    headers = {
        'Authorization': 'OAuth %s' % h
    }

    logging.info(url)
    logging.info(headers)

    r = urlfetch.fetch(url, method=urlfetch.POST, headers=headers)

    logging.info(r.headers)
    logging.info(r.content)

    return [pair.split('=')[1] for pair in r.content.split('&')]


def get_authenticity_token(token):
    url = 'https://api.twitter.com/oauth/authorize?oauth_token=' + token

    content = urlfetch.fetch(url, method=urlfetch.GET).content

    m = re.match(r'(.*)twttr.form_authenticity_token\s?=\s?\'(\w+)', content, re.M | re.I | re.S)

    if m:
        return m.group(2)
    else:
        return ''


def get_token_verify(token, authenticity_token, username, password):
    url = 'https://api.twitter.com/oauth/authorize'
    content = urlfetch.fetch(url, method=urlfetch.POST, payload=urllib.urlencode({
        'authenticity_token': authenticity_token,
        'oauth_token': token,
        'session[username_or_email]': username,
        'session[password]': password
    }), headers={'Content-Type': 'application/x-www-form-urlencoded'}).content

    m = re.match(r'(.*)oauth_verifier=(\w+)', content, re.M | re.I | re.S)

    if m:
        return m.group(2)
    else:
        return ''


def get_access_token(token, secret, verifier):
    uri = 'https://api.twitter.com/oauth/access_token'

    headers = [
        ('oauth_consumer_key', app_key),
        ('oauth_nonce', uuid.uuid4().hex),
        ('oauth_signature_method', 'HMAC-SHA1'),
        ('oauth_timestamp', int(time.time())),
        ('oauth_version', '1.0'),
        ('oauth_token', token),
        ('oauth_verifier', verifier),
        ('oauth_token_secret', secret),
        ]

    headers.sort()

    p = 'POST&%s&%s' % (quote(uri, safe=''), quote(urlencode(headers)))
    signature = hmac.new(app_secret + '&' + secret, p,
                         hashlib.sha1).digest().encode('base64').rstrip()

    headers.append(('oauth_signature', quote(signature)))

    h = ', '.join(['%s="%s"' % (k, v) for (k, v) in headers])

    r = urlfetch.fetch(uri, method=urlfetch.POST, headers={'Authorization': 'OAuth %s' % h})

    content = [pair.split('=')[1] for pair in r.content.split('&')]

    return content


def sign_in(self):
    results = get_request_token()
    token = results[0]
    secret = results[1]

    username = self.request.get('username')
    password = self.request.get('password')

    logging.info(results)
    authenticity_token = get_authenticity_token(token)
    logging.info(authenticity_token)

    token_verify = get_token_verify(token, authenticity_token, username, password)
    logging.info(token_verify)

    content = get_access_token(token, secret, token_verify)
    logging.info(content)

    return json.dumps({
        'token': content[0],
        'tokenSecret': content[1],
        'userId': content[2],
        'screenName': content[3]
    })


def get_relative_url(url, scheme):
    slash = url.find("/", len(scheme + "://"))
    if slash == -1:
        return ''
    else:
        return url[(slash + 1):]


def do_request(self, method=urlfetch.GET):
    if self.request.path == '/dummy':
        self.response.write('hello world')
        return

    if self.request.path == '/sign_in':
        self.response.write(sign_in(self))
        return

    mirror_path = get_relative_url(self.request.url, self.request.scheme)

    logging.info(self.request.body)
    logging.info('https://api.twitter.com/' + mirror_path)
    logging.info(self.request.headers)

    if method == urlfetch.POST or method == urlfetch.PUT:
        result = urlfetch.fetch('https://api.twitter.com/' + mirror_path,
                                payload=self.request.body,
                                method=method,
                                headers=self.request.headers)
    else:
        result = urlfetch.fetch('https://api.twitter.com/' + mirror_path,
                                method=method,
                                headers=self.request.headers)

    logging.info(result.headers)
    logging.info(result.content)

    for key, value in result.headers.iteritems():
        self.response.headers[key] = value

    self.response.write(result.content)


class MainHandler(webapp2.RequestHandler):
    def get(self, base_url):
        do_request(self, urlfetch.GET)

    def post(self, base_url):
        do_request(self, urlfetch.POST)

    def head(self, base_url):
        do_request(self, urlfetch.HEAD)

    def delete(self, base_url):
        do_request(self, urlfetch.DELETE)

    def put(self, base_url):
        do_request(self, urlfetch.PUT)


app = webapp2.WSGIApplication([
    (r"/([^/]+).*", MainHandler)
], debug=True)

