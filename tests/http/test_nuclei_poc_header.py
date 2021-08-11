import os
import sys
import yaml

sys.path.append("../adapter_engine")
from adapter_engine.api import init_adapter_engine
from adapter_engine.lib.core.data import kb, conf
from adapter_engine.lib.core.datatype import AttribDict
from adapter_engine.lib.nuclei.interfaces import Nuclei
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED, FIRST_COMPLETED


def verify_result(file_path):
    init_adapter_engine()
    kb.registered_pocs = AttribDict()
    conf.ipv6 = False
    conf.console_mode = False
    conf.ppt = False
    with open(file_path) as f:
        poc = yaml.safe_load(f)
    nuclei = Nuclei(templates_yaml_json=poc)
    web_result = nuclei.execute(target='http://127.0.0.1:8888')
    # print(web_result)


if __name__ == '__main__':
    futures = []
    with ThreadPoolExecutor() as executor:
        for site, site_list, file_list in os.walk('nuclei-templates/vulnerabilities/'):
            for file_name in file_list:
                abs_filename = os.path.abspath(os.path.join(site, file_name))
                if file_name.endswith('.yaml') and not file_name.startswith('.'):
                    # print(file_name)
                    future = executor.submit(verify_result, abs_filename)
                    futures.append(future)
    wait(futures, return_when=ALL_COMPLETED)
