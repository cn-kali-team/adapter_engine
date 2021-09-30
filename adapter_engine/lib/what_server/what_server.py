# -*- coding: utf-8 -*-
import re
import codecs
import socket
import traceback
import contextlib
import threading
from queue import Queue
from typing import Dict
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED, Future, as_completed

SERVER_SCAN_SOCKET_TIMEOUT = 3  # 等待welcome banner的超时,5秒
SERVER_SCAN_SOCKET_READ_BUFFER_SIZE = 1024  # 接受banner的缓冲区


class ServiceScan:
    def __init__(self, service_probe):
        self.all_probes = service_probe

    def scan(self, web_info):
        host, port = web_info['target'].split(':')
        in_probes, ex_probes = self.filter_probes_by_port(port, self.all_probes)
        host, port = web_info['target'].split(':')
        with ThreadPoolExecutor() as server_executor:
            futures = []
            for probe in in_probes:
                futures.append(server_executor.submit(self.__scan_with_probes, host, port, "TCP", probe))
            for probe in ex_probes:
                futures.append(server_executor.submit(self.__scan_with_probes, host, port, "TCP", probe))
        for future in as_completed(futures):
            # TODO callback
            server_info = future.result()
            if server_info:
                server_info.update(web_info)
                return server_info
        return web_info

    def __scan_with_probes(self, host, port, protocol, probes):
        nmap_fingerprint = {}
        record = self.__send_directive_str_request(
            host, port, protocol, probes, SERVER_SCAN_SOCKET_TIMEOUT
        )
        if record is not None and record.get("match") is not None:
            if bool(record["match"]["version_info"]):
                nmap_fingerprint = record
                return nmap_fingerprint
        return nmap_fingerprint

    def __send_directive_str_request(self, host, port, protocol, probe, timeout):
        """
        根据probe发送数据然后根据回报文的内容判断是否命中
        :param self:
        :param host:
        :param port:
        :param protocol:
        :param probe:
        :param timeout:
        :return:
        """
        proto = probe['protocol']
        payload = probe['directive_str']
        try:
            payload = codecs.escape_decode(payload)[0]
        except Exception:
            pass
        response = ""
        # 对协议类型进行扫描
        if proto.upper() == protocol.upper():
            if protocol.upper() == "TCP":
                response = self.send_tcp_request(host, port, payload, timeout)
            elif protocol.upper() == "UDP":
                response = self.send_udp_request(host, port, payload, timeout)
            else:
                # 对其他类型的进行扫描
                response = ""
                pass
        try:
            nmap_pattern, nmap_fingerprint = self.__match_probe_pattern(response, probe, protocol)
            record = {
                "probe": {
                    "directive_name": probe["directive_name"],
                    "directive_str": probe["directive_str"]
                },
                "match": {
                    "pattern": nmap_pattern,
                    "version_info": nmap_fingerprint
                }
            }
            return record
        except Exception:
            pass

    @staticmethod
    def send_tcp_request(host, port, payload, timeout):
        """
        发送数据包
        :param host: ip
        :param port: 端口
        :param payload: 数据
        :param timeout:超时
        :return:
        """
        data = b''
        try:
            with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as client:
                client.settimeout(timeout)
                client.connect((host, int(port)))
                client.send(payload)
                while True:
                    _ = client.recv(SERVER_SCAN_SOCKET_READ_BUFFER_SIZE)  # TODO: recv连接超时
                    if not _:
                        break
                    data += _
        except Exception:
            # TODO: 尝试做处理
            pass
        return data

    @staticmethod
    def send_udp_request(host, port, payload, timeout):
        """Send udp payloads by port number.
        """
        data = ''
        try:
            with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as client:
                client.settimeout(timeout)
                client.sendto(payload, (host, port))
                while True:
                    _, addr = client.recvfrom(SERVER_SCAN_SOCKET_READ_BUFFER_SIZE)
                    if not _:
                        break
                    data += _
        except Exception:
            pass

        return data

    def __match_probe_pattern(self, data, probe, protocol):
        """
        根据 tcp 返回的数据包内容进行正则匹配
        :param data:
        :param probe:
        :param protocol:
        :return:
        """
        nmap_pattern, nmap_fingerprint = "", {}

        if not data or (not probe['protocol'].upper() == protocol.upper()):
            return nmap_pattern, nmap_fingerprint
        try:
            matches = probe['matches']
            for match in matches:
                pattern = match['pattern']
                pattern_compiled = re.compile(pattern)
                service = match['service']
                # https://github.com/nmap/nmap/blob/master/service_scan.cc#L476
                try:
                    raw_data = codecs.unicode_escape_decode(data)[0]
                except UnicodeDecodeError:
                    raw_data = codecs.unicode_escape_decode(re.escape(data))[0]
                except Exception:
                    raw_data = data
                    pass
                rfind = pattern_compiled.findall(raw_data)
                # rfind = pattern_compiled.search(data)

                if rfind and ("version_info" in match):
                    version_info = match['version_info']

                    rfind = rfind[0]
                    rfind = [rfind] if isinstance(rfind, str) else rfind

                    for index, value in enumerate(rfind):
                        dollar_name = "${}".format(index + 1)
                        version_info = version_info.replace(dollar_name, value)
                    nmap_pattern = pattern
                    nmap_fingerprint = self.match_version_info(version_info)
                    nmap_fingerprint.update({"service": service})

        except Exception:
            traceback.print_exc()
        return nmap_pattern, nmap_fingerprint

    @staticmethod
    def match_version_info(version_info):
        """
        匹配版本信息
        :param version_info:
        :return:
        """
        record = {
            "vendor_product_name": [],
            "version": [],
            "info": [],
            "hostname": [],
            "operating_system": [],
            "cpe_name": []
        }

        if "p/" in version_info:
            regex = re.compile(r"p/([^/]*)/")
            vendor_product_name = regex.findall(version_info)
            record["vendor_product_name"] = vendor_product_name

        if "v/" in version_info:
            regex = re.compile(r"v/([^/]*)/")
            version = regex.findall(version_info)
            record["version"] = version

        if "i/" in version_info:
            regex = re.compile(r"i/([^/]*)/")
            info = regex.findall(version_info)
            clear_info = []
            for i in info:
                clear_info.append(i.encode("unicode-escape").decode())
            record["info"] = clear_info

        if "h/" in version_info:
            regex = re.compile(r"h/([^/]*)/")
            hostname = regex.findall(version_info)
            record["hostname"] = hostname

        if "o/" in version_info:
            regex = re.compile(r"o/([^/]*)/")
            operating_system = regex.findall(version_info)
            record["operating_system"] = operating_system

        if "d/" in version_info:
            regex = re.compile(r"d/([^/]*)/")
            device_type = regex.findall(version_info)
            record["device_type"] = device_type

        if "cpe:/" in version_info:
            regex = re.compile(r"cpe:/a:([^/]*)/")
            cpe_name = regex.findall(version_info)
            record["cpe_name"] = cpe_name
        return record

    def filter_probes_by_port(self, port, probes):
        included = []
        excluded = []

        for probe in probes:
            if probe.get("ports"):
                ports = probe['ports']
                if self.is_port_in_range(port, ports):
                    if not probe.get('rarity'):
                        probe['rarity'] = '0'
                    included.append(probe)
                else:  # exclude ports
                    if not probe.get('rarity'):
                        probe['rarity'] = '0'
                    excluded.append(probe)

            elif probe.get("ssl_ports"):
                ssl_ports = probe['ssl_ports']
                if self.is_port_in_range(port, ssl_ports):
                    if not probe.get('rarity'):
                        probe['rarity'] = '0'
                    included.append(probe)
                else:  # exclude ssl_ports
                    if not probe.get('rarity'):
                        probe['rarity'] = '0'
                    excluded.append(probe)

            else:  # no [ports, ssl_ports] settings
                if not probe.get('rarity'):
                    probe['rarity'] = '0'
                excluded.append(probe)
        # 利用lambda排序,根据端口的稀有度来,稀有度高的可信度高,就提前扫描
        included = sorted(included, key=lambda x: int(x['rarity']))
        excluded = sorted(excluded, key=lambda x: int(x['rarity']))
        return included, excluded

    @staticmethod
    def is_port_in_range(port, nmap_port_rule):
        bret = False

        ports = nmap_port_rule.split(',')  # split into serval string parts
        if str(port) in ports:
            bret = True
        else:
            for nmap_port in ports:
                if "-" in nmap_port:
                    s, e = nmap_port.split('-')
                    if int(port) in range(int(s), int(e)):
                        bret = True
        return bret


class ServerDetectionTemplate(threading.Thread):
    """
    服务识别，接收主机和端口队列
    """

    def __init__(self, web_info_queue, all_target_server_queue, service_probe: Dict, **kwargs):
        """`
        web_info_queue: Web指纹识别后的队列
        all_target_server_queue: 保存web和server信息的队列
        """
        super(ServerDetectionTemplate, self).__init__(**kwargs)
        self.__web_info_queue = web_info_queue
        self.__nmap_service_probe = service_probe
        self.__all_target_server_queue = all_target_server_queue
        self.daemon = True

    def __server_detection_done(self, result: Future):
        web_info = result.result()
        if web_info:
            self.__all_target_server_queue.put(web_info)

    def run(self):
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            server_scan = ServiceScan(service_probe=self.__nmap_service_probe)
            while self.__web_info_queue.qsize():
                web_info = self.__web_info_queue.get()
                server_info_executor = executor.submit(server_scan.scan, web_info)
                server_info_executor.add_done_callback(self.__server_detection_done)
                futures.append(server_info_executor)
        wait(futures, return_when=ALL_COMPLETED)
