import binascii
import re


def match_logic(rule, response):
    try:
        match_part = rule.get('part')  # 要匹配的地方
        if match_part is None and hasattr(response, 'text'):
            match_part = 'body'
        elif (match_part is None and hasattr(response, 'decode')) or match_part == 'all':
            match_part = 'socket'
        match_type = rule.get('type')  # 匹配的类型：status，size，word，regex，binary，dsl

        need_match = None
        if match_part == 'status' or match_type == 'status':
            need_match = response.status_code  # 状态码，int
        elif match_part == 'body':
            need_match = response.content  # 响应内容，byte
        elif match_part == 'header':
            need_match = response.headers  # 响应头，dict
        elif match_part == 'socket':
            need_match = response  # socket报文，byte

        condition = all if rule.get('condition') == 'and' else any  # 匹配的逻辑，并或关系

        is_match = False
        if match_type == 'word':  # 关键字匹配
            is_match = condition([word in str(need_match) for word in rule.get('words', [])])
        elif match_type == 'status':  # 状态码匹配
            is_match = condition([need_match in rule.get('status', [])])
        elif match_type == 'regex':  # 正则匹配
            regex = rule.get('regex', [])
            is_match = condition([re.search(reg, str(need_match), re.IGNORECASE) for reg in regex])
        elif match_type == 'binary':  # 二进制匹配
            binary_list = rule.get('binary', [])
            is_match = condition([binascii.unhexlify(binary) in need_match for binary in binary_list])
        elif match_type == 'size' or match_type == 'dsl':
            # TODO
            pass
        else:
            pass
        if rule.get('negative'):
            return not is_match
        return is_match
    except Exception as E:
        print(E)
        return False
