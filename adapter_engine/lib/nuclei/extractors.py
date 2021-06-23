# 提取器
import re


class Extractor:
    def __init__(self, extractors, response):
        self.extractors = extractors
        self.response = response
        self.extractor_dict = {}
        self.get_extractor()

    def get_extractor(self):
        for extractor in self.extractors:
            e_type = extractor.get('type')  # word
            e_part = extractor.get('part', 'body')  # 要匹配的位置
            e_name = extractor.get('name')
            group = extractor.get('group', 0)
            need_extra = None
            if e_part == 'status':
                need_extra = self.response.status_code
            elif e_part == 'body':
                need_extra = self.response.text
            elif e_part == 'header':
                need_extra = self.response.headers
            if e_type == 'regex':
                regex = extractor.get('regex')[0]
                need_extra = '\r\n'.join(
                    [s + ': ' + need_extra[s] for s in need_extra]) if e_part == 'header' else need_extra
                e_value = re.findall(regex, need_extra)[group] if re.findall(regex, need_extra) else None
                if e_value:
                    self.extractor_dict.update({e_name: e_value})
            elif e_type == 'kval':
                kval = extractor.get('kval')[0]
                e_value = need_extra.get(kval)
                if e_value:
                    self.extractor_dict.update({e_name: e_value})
        return self.extractor_dict

    def get_extractors_by_name(self, context_dict, variable_node):
        set_diff = list(set(variable_node).difference(set(context_dict.keys())))
        my_extractor_dict = {}
        for name in set_diff:
            if name in self.extractor_dict:
                my_extractor_dict.update({name: self.extractor_dict.get(name)})
        return my_extractor_dict
