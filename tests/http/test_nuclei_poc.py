import unittest
from adapter_engine.api import init_adapter_engine
from adapter_engine.lib.core.data import kb, conf
from adapter_engine.lib.core.datatype import AttribDict
from adapter_engine.lib.core.register import load_yaml_to_module


class TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def verify_result(self):
        init_adapter_engine()
        kb.registered_pocs = AttribDict()
        conf.ipv6 = False
        conf.console_mode = False
        conf.ppt = False
        poc = {'id': 'basic-get',
               'info': {'name': 'Test GET Request', 'author': 'kali-team', 'severity': 'info'},
               'requests': [
                   {'method':
                        'GET',
                    'path':
                        ['{{BaseURL}}'],
                    'matchers':
                        [{'type':
                              'word',
                          'words':
                              ['origin']
                          }
                         ]
                    }
               ]
               }
        load_yaml_to_module(yaml_json=poc, fullname='web')
        web_result = kb.registered_pocs['web'].execute(target='https://httpbin.org/ip')
        self.assertTrue(web_result.get('status') == 1)

    def test_import_run(self):
        self.verify_result()
