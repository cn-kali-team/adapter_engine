import unittest
from adapter_engine.api import init_adapter_engine
from adapter_engine.lib.core.data import kb, conf
from adapter_engine.lib.core.datatype import AttribDict
from adapter_engine.lib.core.register import load_file_to_module


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
        load_file_to_module('tests/pocsuite3_poc.py', 'web')
        web_result = kb.registered_pocs['web'].execute(target='https://httpbin.org/ip')
        self.assertTrue(web_result.status == 1)

    def test_import_run(self):
        self.verify_result()
