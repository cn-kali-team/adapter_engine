# -*- coding:utf-8 -*-
from hashlib import md5
from adapter_engine.lib.nuclei.protocols import nuclei_request, nuclei_network


class Nuclei(object):
    def __init__(self, templates_yaml_json):
        self.__templates = templates_yaml_json

    def __dir__(self):
        return ['wtf']

    def execute(self, target, params=None):
        if params is None:
            ext_result = {}
        res = {}
        template_name = self.__templates.get('id', md5(str(self.__templates).encode()).hexdigest())
        match_status = False
        ext_result = params if isinstance(params, dict) else {}
        if self.__templates.get('requests'):
            match_status, template_info = nuclei_request(self.__templates, target)
        elif self.__templates.get('network'):
            match_status, template_info = nuclei_network(self.__templates, target)
        else:
            pass
        template_info = self.__templates.get('info', {})
        res.setdefault('status', int(match_status))
        res.setdefault('name', template_name)
        res.setdefault('result', template_info)
        res.setdefault('params', ext_result)
        return res
