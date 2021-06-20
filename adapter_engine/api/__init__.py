from adapter_engine.lib.core.data import conf, kb, logger
from adapter_engine.lib.core.datatype import AttribDict
from adapter_engine.lib.core.enums import POC_CATEGORY, VUL_TYPE
from adapter_engine.lib.core.option import init, init_options
from adapter_engine.lib.core.poc import POCBase, Output
from adapter_engine.lib.core.register import (load_file_to_module, load_string_to_module, register_poc)
from adapter_engine.lib.request import requests

__all__ = (
    'requests', 'POCBase', 'Output', 'AttribDict', 'POC_CATEGORY', 'VUL_TYPE',
    'register_poc', 'conf', 'kb', 'logger', 'load_file_to_module',
    'load_string_to_module', 'init_adapter_engine', 'get_poc_options')


def get_poc_options(poc_obj=None):
    poc_obj = poc_obj or kb.current_poc
    return poc_obj.get_options()


def init_adapter_engine(options=None):
    if options is None:
        options = {}
    init_options(options)
    init()
