import socket
from queue import Queue

from adapter_engine.lib.core.data import conf
from adapter_engine.lib.core.data import kb
from adapter_engine.lib.core.data import logger
from adapter_engine.lib.core.data import merged_options
from adapter_engine.lib.core.datatype import AttribDict
from adapter_engine.lib.core.enums import HTTP_HEADER
from adapter_engine.lib.core.settings import DEFAULT_USER_AGENT
from adapter_engine.lib.request.patch import patch_all


def _set_http_referer():
    if conf.referer:
        conf.http_headers[HTTP_HEADER.REFERER] = conf.referer


def _set_http_cookie():
    if conf.cookie:
        if isinstance(conf.cookie, dict):
            conf.http_headers[HTTP_HEADER.COOKIE] = '; '.join(map(lambda x: '='.join(x), conf.cookie.items()))
        else:
            conf.http_headers[HTTP_HEADER.COOKIE] = conf.cookie


def _set_http_host():
    if conf.host:
        conf.http_headers[HTTP_HEADER.HOST] = conf.host


def _set_http_extra_headers():
    if conf.headers:
        conf.headers = conf.headers.split("\n") if "\n" in conf.headers else conf.headers.split("\\n")
        for header_value in conf.headers:
            if not header_value.strip():
                continue

            if header_value.count(':') >= 1:
                header, value = (_.lstrip() for _ in header_value.split(":", 1))
                if header and value:
                    if header not in conf.http_headers:
                        conf.http_headers[header] = value


def _set_network_timeout():
    if conf.timeout:
        conf.timeout = float(conf.timeout)
        if conf.timeout < 3.0:
            conf.timeout = 3.0
    else:
        conf.timeout = 30.0

    socket.setdefaulttimeout(conf.timeout)


def _set_conf_attributes():
    """
    This function set some needed attributes into the configuration
    singleton.
    """

    debug_msg = "initializing the configuration"
    logger.debug(debug_msg)

    conf.url = None
    conf.url_file = None
    conf.mode = 'verify'
    conf.poc = None
    conf.cookie = None
    conf.host = None
    conf.referer = None
    conf.agent = None
    conf.headers = None
    conf.random_agent = None
    conf.proxy = None
    conf.proxy_cred = None
    conf.proxies = {}
    conf.timeout = 30
    conf.retry = 0
    conf.delay = 0
    conf.http_headers = {}
    conf.agents = [DEFAULT_USER_AGENT]  # 数据源从插件加载的时候无默认值需要处理
    conf.login_user = None
    conf.login_pass = None
    conf.shodan_token = None
    conf.fofa_user = None
    conf.fofa_token = None
    conf.censys_uid = None
    conf.censys_secret = None
    conf.dork = None
    conf.dork_zoomeye = None
    conf.dork_shodan = None
    conf.dork_fofa = None
    conf.dork_censys = None
    conf.max_page = 1
    conf.search_type = 'host'
    conf.comparison = False
    conf.vul_keyword = None
    conf.ssvid = None
    conf.plugins = []
    conf.threads = 1
    conf.batch = False
    conf.check_requires = False
    conf.quiet = False
    conf.update_all = False
    conf.verbose = 1

    conf.ipv6 = False
    conf.multiple_targets = False
    conf.pocs_path = None
    conf.output_path = None
    conf.plugin_name = None
    conf.plugin_code = None
    conf.console_mode = False
    conf.show_version = False
    conf.api = False  # api for zipoc
    conf.ppt = False


def _set_kb_attributes(flush_all=True):
    """
    This function set some needed attributes into the knowledge base
    singleton.
    """

    debug_msg = "initializing the knowledge base"
    logger.debug(debug_msg)

    kb.abs_file_paths = set()
    kb.os = None
    kb.os_version = None
    kb.arch = None
    kb.dbms = None
    kb.auth_header = None
    kb.counters = {}
    kb.multi_thread_mode = False
    kb.thread_continue = True
    kb.thread_exception = False
    kb.word_lists = None
    kb.single_log_flags = set()

    kb.cache = AttribDict()
    kb.cache.addrinfo = {}
    kb.cache.content = {}
    kb.cache.regex = {}

    kb.data = AttribDict()
    kb.data.local_ips = []
    kb.data.clients = []
    kb.plugins = AttribDict()
    kb.plugins.targets = AttribDict()
    kb.plugins.pocs = AttribDict()
    kb.plugins.results = AttribDict()
    kb.results = []
    kb.current_poc = None
    kb.registered_pocs = AttribDict()
    kb.task_queue = Queue()
    kb.comparison = None


def _merge_options(input_options, override_options):
    """
    Merge command line options with configuration file and default options.
    """
    if hasattr(input_options, "items"):
        input_options_items = input_options.items()
    else:
        input_options_items = input_options.__dict__.items()

    for key, value in input_options_items:
        if key not in conf or value not in (None, False) or override_options:
            conf[key] = value

    merged_options.update(conf)


def init_options(input_options=None, override_options=False):
    if input_options is None:
        input_options = AttribDict()
    _set_conf_attributes()
    _set_kb_attributes()
    _merge_options(input_options, override_options)


def init():
    """
    Set attributes into both configuration and knowledge base singletons
    based upon command line and configuration file options.
    """
    if any((conf.url, conf.url_file, conf.plugins)):
        _set_http_cookie()
        _set_http_host()
        _set_http_referer()
        _set_http_extra_headers()

    _set_network_timeout()
    patch_all()
