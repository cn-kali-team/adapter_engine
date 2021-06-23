import re


def parse_target_url(url):
    """
    Parse target URL
    """
    ret = url
    if not re.search("^http[s]*://", ret, re.I) and not re.search("^ws[s]*://", ret, re.I):
        if re.search(":443[/]*$", ret):
            ret = "https://" + ret
        else:
            ret = "http://" + ret
    return ret
