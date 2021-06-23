import binascii
import json
import socket
from urllib.parse import urlparse
import requests
from adapter_engine.lib.nuclei.template import Template
from adapter_engine.lib.nuclei.extractors import Extractor
from adapter_engine.lib.nuclei.matchers import match_logic
from adapter_engine.lib.core.settings import DEFAULT_USER_AGENT
from typing import Any


def send_requests(rtype, session: Any, requests_step, target, path_or_raw=None, last_response=None):
    if not session:
        session = requests.Session()
    parse_result = urlparse(target)
    context_dict = {"Hostname": parse_result.netloc, 'BaseURL': parse_result.scheme + '://' + parse_result.netloc}
    extractors = requests_step.get('extractors', [])
    template_path_or_raw = Template(path_or_raw)
    session.allow_redirects = requests_step.get('redirects', False)
    session.max_redirects = requests_step.get('max-redirects', 3)
    session.headers = requests_step.get('headers', {})
    if not session.headers.get('User-Agent'):
        session.headers.setdefault('User-Agent', DEFAULT_USER_AGENT)
    data = requests_step.get('body')
    kw = {'timeout': 15}
    if data:
        try:
            kw = {"json": json.loads(data)}
        except json.decoder.JSONDecodeError:
            kw = {"data": data}
    variable_node = template_path_or_raw.variable_node  # 当前的占位符
    if extractors and last_response:
        extractor = Extractor(extractors=extractors, response=last_response)
        e_context_dict = extractor.get_extractors_by_name(context_dict=context_dict,
                                                          variable_node=variable_node)
        if e_context_dict:
            context_dict.update(**e_context_dict)
    try:
        raw_or_path = template_path_or_raw.render(context_dict)  # 根据占位符生成payload
    except AttributeError:
        return None, None
    try:
        if rtype == 'raw':
            response = requests.raw(url=context_dict.get('BaseURL'), data=raw_or_path)
        else:
            response = session.request(method=requests_step.get('method', 'GET'), url=raw_or_path, **kw)
    except (requests.exceptions.ReadTimeout, ValueError, Exception):
        response = None
    if extractors and response:
        extractor = Extractor(extractors=extractors, response=response)
        return response, extractor.extractor_dict
    else:
        return response, None


def send_network(target, rtype, data, read):
    try:
        res = urlparse(target)
        if res.netloc:
            ip, port = res.netloc.split(':')
        else:
            ip, port = target.split(':')
    except Exception:
        return None
    if rtype == 'hex':
        data = binascii.a2b_hex(data)
    else:
        data = data.encode()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        s.send(data)
        result = s.recv(read)
        return result
    except Exception as e:
        return None


def nuclei_request(templates, target):
    # 集成了poc验证
    other_matchers = templates.get('matchers')  # 有些poc把匹配写在外面了
    session = None
    for step in templates.get('requests'):
        matchers = step.get('matchers', []) if step.get('matchers') else other_matchers  # 当前级没有规则就用之前的
        cookie_reuse = step.get('cookie-reuse', False)
        if cookie_reuse:
            session = requests.Session()
        matchers_condition = all if step.get('matchers-condition') == 'and' else any  # 匹配逻辑并或关系
        last_time_response = None  # 上一次的响应报文
        match_status = False
        request_steps, rtype = [], 'path'
        if step.get('raw'):
            rtype = 'raw'
            request_steps = step.get('raw')
        elif step.get('path'):
            rtype = 'path'
            request_steps = step.get('path')
        for path_or_raw in request_steps:
            response, extractor = send_requests(rtype=rtype, session=session, requests_step=step,
                                                path_or_raw=path_or_raw, target=target,
                                                last_response=last_time_response)
            last_time_response = response
            if matchers and response:
                match_status = matchers_condition([match_logic(match, response) for match in matchers])
        if match_status:
            return match_status, step
    return False, {}


def nuclei_network(templates, target):
    other_matchers = templates.get('matchers')  # 有些poc把匹配写在外面了
    match_status = False
    for step in templates.get('network'):
        matchers_condition = all if step.get('matchers-condition') == 'and' else any  # 匹配逻辑并或关系
        matchers = step.get('matchers', []) if step.get('matchers') else other_matchers  # 当前级没有规则就用之前的
        for n_input in step.get('inputs', []):
            rtype = n_input.get('type')
            data = n_input.get('data')
            read = n_input.get('read', 1024)
            response = send_network(target=target, rtype=rtype, data=data, read=read)
            if matchers and response:
                match_status = matchers_condition([match_logic(match, response) for match in matchers])
        if match_status:
            step.pop('host')
            return match_status, step
    return False, {}
