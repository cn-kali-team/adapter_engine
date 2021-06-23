import ast
import hashlib
import importlib.machinery
import importlib.util
import inspect
import pickle
from importlib.abc import Loader
import marshal
from adapter_engine.lib.core.data import kb
from adapter_engine.lib.core.data import logger
from adapter_engine.lib.nuclei.interfaces import Nuclei


class MyVisitor(ast.NodeTransformer):

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == 'lib.api' or node.module == 'pocsuite3.api':
            node.module = 'adapter_engine.api'
        return node


class PocLoader(Loader):
    def __init__(self, fullname, path):
        self.fullname = fullname
        self.path = path
        self.data = None
        self.obf_data = None

    def set_data(self, data):
        self.data = data

    def set_obf_data(self, data):
        self.obf_data = data

    def get_filename(self, fullname):
        return self.path

    def get_data(self, filename):
        if filename.startswith('pocsuite://') and self.data:
            data = self.data
        elif filename.startswith('obf://') and self.obf_data:
            return self.obf_data
        else:
            with open(filename, encoding='utf-8') as f:
                code = f.read()
                ast_dump = ast.parse(code)
                optimizer = MyVisitor()
                data = optimizer.visit(ast_dump)
        return data

    def exec_module(self, module):
        filename = self.get_filename(self.fullname)
        poc_code = self.get_data(filename)
        obj = compile(poc_code, filename, 'exec', dont_inherit=True, optimize=-1)
        try:
            exec(obj, module.__dict__)
        except Exception as err:
            logger.error("Poc: '{}' exec arise error: {} ".format(filename, err))

    def exec_obf_module(self, module):
        filename = self.get_filename(self.fullname)
        poc_code = self.get_data(filename)
        try:
            exec(marshal.loads(poc_code), module.__dict__)
        except Exception as err:
            logger.error("Poc: '{}' exec arise error: {} ".format(filename, err))

    def exec_yaml_module(self, module):
        filename = self.get_filename(self.fullname)
        poc_code = self.get_data(filename)
        try:
            module = pickle.loads(poc_code)
            return module
        except Exception as err:
            logger.error("Poc: '{}' exec arise error: {} ".format(filename, err))


def load_file_to_module(file_path, module_name=None):
    if '' not in importlib.machinery.SOURCE_SUFFIXES:
        importlib.machinery.SOURCE_SUFFIXES.append('')
    try:
        module_name = 'pocs_{0}'.format(hashlib.md5(file_path).hexdigest()) if module_name is None else module_name
        spec = importlib.util.spec_from_file_location(module_name, file_path, loader=PocLoader(module_name, file_path))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        poc_model = kb.registered_pocs[module_name]
    except KeyError:
        poc_model = None
    except ImportError:
        error_msg = "load module failed! '{}'".format(file_path)
        logger.error(error_msg)
        raise
    return poc_model


def load_obf_to_module(code_string, fullname=None):
    try:
        module_name = 'pocs_{0}'.format(hashlib.md5(code_string).hexdigest()) if fullname is None else fullname
        file_path = 'pocsuite://{0}'.format(module_name)
        poc_loader = PocLoader(module_name, file_path)
        poc_loader.set_data(code_string)
        spec = importlib.util.spec_from_file_location(module_name, file_path, loader=poc_loader)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        poc_model = kb.registered_pocs[module_name]
    except KeyError:
        poc_model = None
    except ImportError:
        error_msg = "load module '{0}' failed!".format(fullname)
        logger.error(error_msg)
        raise
    return poc_model


def load_string_to_module(code_string, fullname=None):
    try:
        module_name = 'pocs_{0}'.format(hashlib.md5(code_string).hexdigest()) if fullname is None else fullname
        file_path = 'obf://{0}'.format(module_name)
        poc_loader = PocLoader(module_name, file_path)
        poc_loader.set_obf_data(code_string)
        spec = importlib.util.spec_from_file_location(module_name, file_path, loader=poc_loader)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_obf_module(mod)
        poc_model = kb.registered_pocs[module_name]
    except KeyError:
        poc_model = None
    except ImportError:
        error_msg = "load module '{0}' failed!".format(fullname)
        logger.error(error_msg)
        raise
    return poc_model


def load_obf_yaml_to_module(yaml_json, fullname=None):
    try:
        name = hashlib.md5(str(yaml_json).encode()).hexdigest() if fullname is None else fullname
        file_path = 'obf://{0}'.format(name)
        poc_loader = PocLoader(name, file_path)
        poc_loader.set_obf_data(yaml_json)
        spec = importlib.util.spec_from_file_location(name, file_path, loader=poc_loader)
        mod = importlib.util.module_from_spec(spec)
        mods = spec.loader.exec_yaml_module(mod)
        poc_model = kb.registered_pocs[name] = mods
    except KeyError:
        poc_model = None
    except ImportError:
        error_msg = "load module '{0}' failed!".format(fullname)
        logger.error(error_msg)
        raise
    return poc_model


def load_yaml_to_module(yaml_json, fullname=None):
    try:
        name = yaml_json.get('id', hashlib.md5(str(yaml_json).encode()).hexdigest()) if fullname is None else fullname
        file_path = 'obf://{0}'.format(name)
        poc_loader = PocLoader(name, file_path)
        nuclei_ins = Nuclei(templates_yaml_json=yaml_json)
        plugins_code = pickle.dumps(nuclei_ins)
        poc_loader.set_obf_data(plugins_code)
        spec = importlib.util.spec_from_file_location(name, file_path, loader=poc_loader)
        mod = importlib.util.module_from_spec(spec)
        mods = spec.loader.exec_yaml_module(mod)
        poc_model = kb.registered_pocs[name] = mods
    except KeyError:
        poc_model = None
    except ImportError:
        error_msg = "load module '{0}' failed!".format(fullname)
        logger.error(error_msg)
        raise
    return poc_model


def register_poc(poc_class):
    module = poc_class.__module__.split('.')[0]
    if module in kb.registered_pocs:
        kb.current_poc = kb.registered_pocs[module]
        return

    kb.registered_pocs[module] = poc_class()
    kb.current_poc = kb.registered_pocs[module]
