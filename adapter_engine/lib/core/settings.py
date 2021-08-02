# Encoding used for Unicode data
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " \
                     "Chrome/92.0.4515.107 Safari/537.36 "
DEFAULT_HEADERS = {
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'DNT': '1',  # Do Not Track request header
    'User-Agent': DEFAULT_USER_AGENT,
    'Upgrade-Insecure-Requests': '1'  #
}
