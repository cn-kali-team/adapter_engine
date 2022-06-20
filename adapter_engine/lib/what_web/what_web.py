# -*- coding: utf-8 -*-
import base64
import re
import codecs
import hashlib
from abc import ABC
from pathlib import Path
import requests
import threading
import urllib3
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED, Future
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin
from adapter_engine.lib.core.settings import DEFAULT_HEADERS
from queue import Queue, Full, Empty


def mmh3(key, seed=0x0):
    key = bytearray(key)

    def f_mix(h):
        h ^= h >> 16
        h = (h * 0x85ebca6b) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 0xc2b2ae35) & 0xFFFFFFFF
        h ^= h >> 16
        return h

    length = len(key)
    n_blocks = int(length / 4)

    h1 = seed

    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    for block_start in range(0, n_blocks * 4, 4):
        k1 = key[block_start + 3] << 24 | \
             key[block_start + 2] << 16 | \
             key[block_start + 1] << 8 | \
             key[block_start + 0]

        k1 = (c1 * k1) & 0xFFFFFFFF
        k1 = (k1 << 15 | k1 >> 17) & 0xFFFFFFFF  # inlined ROTL32
        k1 = (c2 * k1) & 0xFFFFFFFF

        h1 ^= k1
        h1 = (h1 << 13 | h1 >> 19) & 0xFFFFFFFF  # inlined ROTL32
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF

    tail_index = n_blocks * 4
    k1 = 0
    tail_size = length & 3

    if tail_size >= 3:
        k1 ^= key[tail_index + 2] << 16
    if tail_size >= 2:
        k1 ^= key[tail_index + 1] << 8
    if tail_size >= 1:
        k1 ^= key[tail_index + 0]

    if tail_size > 0:
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = (k1 << 15 | k1 >> 17) & 0xFFFFFFFF  # inlined ROTL32
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    unsigned_val = f_mix(h1 ^ length)
    if unsigned_val & 0x80000000 == 0:
        return unsigned_val
    else:
        return -((unsigned_val ^ 0xFFFFFFFF) + 1)


class WhatWeb:

    def __init__(self, fingerprints, response=None):
        """`
        fingerprints: 指纹库
        response: 首页的请求响应
        """
        self.cache = {}
        self.response = response
        self.fingerprints = fingerprints
        self.web_name_list = []
        self.web_info_list = []
        self.not_allow_lang = []
        if response:  # 判断是否为Web的时候已经把请求头的语言提取出来了
            self.not_allow_lang = self.__get_not_allow_lang(response=response)

    @staticmethod
    def __get_not_allow_lang(response):
        cookie_to_lang_map = {'PHPSESSID': '.php',
                              'JSESSIONID': '.jsp',
                              'ASPSESSION': '.asp',
                              }
        for flag in cookie_to_lang_map:
            if flag in str(response.cookies):
                cookie_to_lang_map.pop(flag)
                return cookie_to_lang_map.values()
        return []

    def what_web_scan(self, http_host_port):
        self.web_name_list = []
        result = self.__scan_in_thread(http_host_port)
        return result

    def is_allow_uri(self, path):
        # 不允许访问图标的path,不允许访问已经识别到的网站语言之外的语言后缀,因为图标的识别已经在icon识别的时候已经执行过了
        if set(Path(path.lower()).suffixes).issubset(['.ico', '.gif', '.png', '.jpg']) or any(
                [lang in Path(path.lower()).suffixes for lang in self.not_allow_lang]):
            return False
        return True

    def __scan_in_thread(self, http_host_port):
        for fingerprint in self.fingerprints:
            self.scan_with_cms_first(http_host_port, fingerprint.get("path"), fingerprint)
        return list(set(self.web_name_list))

    def match_web_rules(self, fingerprints, web_info=None):
        if 'status_code' in web_info and 'headers' in web_info and 'text' in web_info:
            status_code = web_info.get('status_code', 0)
            headers = web_info.get('headers', {})
            text = web_info.get('text', '').lower()
            favicons = set([icon.get("md5") for icon in web_info.get('icon', [])])
        else:
            return False
        for hk in list(headers.keys()):
            headers[hk.lower()] = headers.pop(hk).lower()
        match_status_code = fingerprints['status_code']
        match_headers = fingerprints['headers']
        match_keyword = fingerprints['keyword']
        match_favicon = set(fingerprints['favicon_hash'])
        if match_favicon and favicons.intersection(match_favicon):
            self.web_name_list.append(fingerprints['name'])
            return False
        if not any([match_status_code, match_headers, match_keyword]):
            return False
        if match_status_code != 0 and (int(status_code) != int(match_status_code)):
            return False
        if match_headers:
            flag = False
            for key, value in match_headers.items():
                if not headers.get(key):  # 连这个Key都没有的
                    flag = True
                elif value != '*' and value.lower() not in headers.get(key, "").lower():  # 不是*，匹配不到值
                    flag = True
            if flag:
                return False
        if match_keyword and any([kw.lower() not in text for kw in match_keyword]):
            return False
        self.web_name_list.append(fingerprints['name'])

    def fingerprint_helper(self, response):
        web_fingerprint_dict = {}
        try:
            icon_parser = FaviconIcon()
            icon_parser.feed(response.text)
            urllib3.disable_warnings()
            if response.request.path_url == '/yunsee_not_found_test':
                path = '/404'
            elif response.request.path_url == '/':
                icon_parser.favicon_ico.add('favicon.ico')
                path = response.request.path_url
            else:
                path = response.request.path_url
            web_fingerprint_dict.setdefault("path", path)
            web_fingerprint_dict.setdefault("status_code", response.status_code)
            web_fingerprint_dict.setdefault("headers", dict(response.headers))
            web_fingerprint_dict.setdefault("text", response.text)

            icon_info_list = []
            if icon_parser.favicon_ico:
                for icon_path in set(urljoin("", path) for path in icon_parser.favicon_ico):
                    icon_url = urljoin(response.url, icon_path)
                    icon_resp = self._send_request(response.url, icon_path)
                    if icon_resp.status_code != 200:
                        continue
                    icon_info = {
                        'path': urlparse(icon_url).path,
                        'md5': hashlib.md5(icon_resp.content).hexdigest(),
                        'mmh3': mmh3(codecs.encode(icon_resp.content, "base64")),
                        'base64': base64.b64encode(icon_resp.content).decode('utf-8')
                    }
                    icon_info_list.append(icon_info)
            web_fingerprint_dict.setdefault('icon', icon_info_list)
            if response.is_redirect:
                web_fingerprint_dict.setdefault("is_redirect", True)
                web_fingerprint_dict.setdefault("next_url", response.next.url)
            else:
                web_fingerprint_dict.setdefault("is_redirect", False)
                web_fingerprint_dict.setdefault("next_url", None)
            return web_fingerprint_dict
        except Exception:
            return web_fingerprint_dict

    def scan_with_cms_first(self, host, path, fingerprints):
        if path == '/' and self.response:
            response = self.response
        else:
            response = self._send_request(host, path)
        web_info = self.fingerprint_helper(response=response)
        self.web_info_list.append(web_info)
        self.match_web_rules(web_info=web_info, fingerprints=fingerprints)
        if web_info.get('is_redirect'):
            response = self._send_request(response.next.url)
            web_info = self.fingerprint_helper(response=response)
            self.match_web_rules(web_info=web_info, fingerprints=fingerprints)
            self.web_info_list.append(web_info)

    def _send_request(self, host, path=None, **kwargs):
        cache_key = host + path
        if cache_key in self.cache:
            return self.cache.get(cache_key)
        urllib3.disable_warnings()
        kwargs.setdefault("timeout", 3)
        try:
            url = urljoin(host, path)
            response = requests.get(url, headers=DEFAULT_HEADERS, verify=False, allow_redirects=False, **kwargs)
        except Exception:
            response = None
        self.cache.setdefault(cache_key, response)
        return response


class FaviconIcon(HTMLParser, ABC):
    def __dir__(self):
        pass

    def __init__(self):
        HTMLParser.__init__(self)
        self.favicon_ico = set()

    def handle_starttag(self, tag, attrs):
        if tag == 'link':
            attributes = dict(attrs)
            if attributes['rel'] in ['shortcut icon', 'icon']:
                href = urlparse(attributes['href']).path
                if not re.search(r'\d{2,4}x\d{2,4}', href, re.IGNORECASE):
                    self.favicon_ico.add(href)


class TitleParser(HTMLParser, ABC):
    def __dir__(self):
        pass

    def __init__(self):
        HTMLParser.__init__(self)
        self.match = False
        self.title = None

    def handle_starttag(self, tag, attrs):
        self.match = tag == 'title'

    def handle_data(self, data):
        if self.match:
            self.title = data
            self.match = False


class WebDetectionTemplate(threading.Thread):
    """
    Web识别，接收主机和端口队列
    """

    def __init__(self, host_open_port_queue: Queue, web_info_queue: Queue, web_fingerprint, **kwargs):
        """`
        host_open_port_queue: 主机名和开放的端口队列
        web_info_queue: 保存web信息的队列
        web_fingerprint: 指纹库
        """
        super(WebDetectionTemplate, self).__init__(**kwargs)
        self.__host_port_queue = host_open_port_queue
        self.__web_fingerprint = web_fingerprint
        self.bad_status_code = []  # [404, 400, 403, 500, 502, 503]
        self.__web_info_queue = web_info_queue
        self.daemon = True

    def __web_detection_done(self, future: Future):
        web_info_result = future.result()
        if web_info_result:
            self.__web_info_queue.put(web_info_result)

    @staticmethod
    def __get_title(response):
        try:
            title_parser = TitleParser()
            title_parser.feed(response.text)
            title = title_parser.title
            title_parser.close()
            return title
        except Exception:
            return None

    def __try_is_web(self, web_info_result):
        host_port = web_info_result['target']
        for scheme in ['https', 'http']:
            try:
                urllib3.disable_warnings()
                response = requests.get(scheme + "://" + host_port, timeout=3, headers=DEFAULT_HEADERS, verify=False,
                                        allow_redirects=False)
                if response.status_code:
                    web_name = []
                    web_info = []
                    if response.status_code not in self.bad_status_code:
                        what_web_ins = WhatWeb(response=response, fingerprints=self.__web_fingerprint.copy())
                        web_name = what_web_ins.what_web_scan(scheme + "://" + host_port)
                        web_info = what_web_ins.web_info_list
                    title = self.__get_title(response)
                    web_info_result['is_web'] = True
                    web_info_result['what_web'] = list(set(web_name))
                    web_info_result['scheme'] = scheme
                    web_info_result['title'] = title
                    web_info_result['status_code'] = response.status_code
                    web_info_result['web_info'] = web_info
                    return web_info_result
            except Exception:
                pass
        web_info_result['is_web'] = False
        web_info_result['what_web'] = []
        web_info_result['scheme'] = None
        web_info_result['title'] = None
        web_info_result['status_code'] = 0
        web_info_result['web_info'] = []
        return web_info_result

    def run(self):
        with ThreadPoolExecutor() as executor:
            futures = []
            while not self.__host_port_queue.empty():
                try:
                    host, port = self.__host_port_queue.get_nowait()
                    web_executor = executor.submit(self.__try_is_web, {'target': f'{host}:{port}'})
                    web_executor.add_done_callback(self.__web_detection_done)
                    futures.append(web_executor)
                except Empty:
                    pass
        wait(futures, return_when=ALL_COMPLETED)
