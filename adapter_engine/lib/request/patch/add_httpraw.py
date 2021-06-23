import requests
from adapter_engine.thirdparty.requests_raw import raw


def patch_add_raw():
    requests.raw = raw
