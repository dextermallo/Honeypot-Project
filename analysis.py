import pycountry
import re
import json
from typing import List
from urllib.request import urlopen


HTTP_LOG_PATH = 'data/dist/honeypot-1.log'
CORAZA_LOG_PATH = './data/dist/coraza.log'
MALICIOUS_INFO_PATH = './data/dist/malicious-request-time-with-ip.log'
IGNORED_HEADER_LIST = ["X-Forwarded-For", "Accept", "Accept-Encoding", "Accept-Language",
                       "Host", "User-Agent", "Origin", "Accept-Charset", "Content-Type",
                       "Transfer-Encoding", "DNT", "Connection", "Upgrade-Insecure-Requests",
                       "X-Datadog-Parent-Id", "X-Datadog-Sampling-Priority", "X-Datadog-Trace-Id",
                       "X-Requested-With", "Cache-Control", "Pragma",
                       "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest",
                       "Sec-Gpc"
                       ]

class DailySegment:
    date: str
    daily_activity_cnt: int
    daily_action: dict
    daily_ip_set: set
    daily_ip_set_cnt: dict # ip: cnt
    daily_username_cnt: dict
    daily_password_cnt: dict

    def __init__(self, date: str):
        self.date = date
        self.daily_activity_cnt = 0
        self.daily_action = dict()
        self.daily_ip_set = set()
        self.daily_ip_set_cnt = dict()
        self.daily_username_cnt = dict()
        self.daily_password_cnt = dict()

class HttpContext:
    segments: dict # date: DailySegment
    ip_set: set
    ip_set_cnt: dict
    activity_cnt: int
    action: dict
    username_cnt: dict
    password_cnt: dict

    def __init__(self):
        self.segments = dict()
        self.ip_set = set()
        self.ip_set_cnt = dict()
        self.activity_cnt = 0
        self.action = dict()
        self.username_cnt = dict()
        self.password_cnt = dict()

class FrameworkContext:
    rules: dict # rule: cnt
    
    def __init__(self):
        self.rules = dict()

def get_http_log_overview() -> HttpContext:

    ctx = HttpContext()

    with open(HTTP_LOG_PATH) as f:
        lines = f.readlines()

        for line in lines:
            line_json = json.loads(line)
            time: str = line_json["timestamp"].split("T")[0]
            ip: str = line_json["src_ip"].split(":")[0]
            action: str = line_json["action"]

            # override connection action by reading value from data
            if "data" in line_json:
                action = line_json["data"]["method"]

            username: str = line_json["username"] if "username" in line_json else None
            password: str = line_json["password"] if "password" in line_json else None

            if not time in ctx.segments:
                ctx.segments[time] = DailySegment(time)

            segment: DailySegment = ctx.segments[time]
            segment.daily_activity_cnt += 1
            segment.daily_ip_set.add(ip)
            
            if action != "connection":
                segment.daily_ip_set_cnt[ip] = segment.daily_ip_set_cnt[ip] + 1 if ip in segment.daily_ip_set_cnt else 1
            segment.daily_action[action] = segment.daily_action[action] + 1 if action in segment.daily_action else 1
            if username:
                segment.daily_username_cnt[username] = segment.daily_username_cnt[username] + 1 if username in segment.daily_username_cnt else 1
            if password:
                segment.daily_password_cnt[password] = segment.daily_password_cnt[password] + 1 if password in segment.daily_password_cnt else 1

    f.close()

    for date in ctx.segments:
        s: DailySegment = ctx.segments[date]

        ctx.activity_cnt += s.daily_activity_cnt
        ctx.ip_set = ctx.ip_set.union(s.daily_ip_set)

        for key in s.daily_action:
            if key not in ctx.action:
                ctx.action[key] = 0
            ctx.action[key] += s.daily_action[key]
    
        for key in s.daily_username_cnt:
            if key not in ctx.username_cnt:
                ctx.username_cnt[key] = 0
            ctx.username_cnt[key] += s.daily_username_cnt[key]
        
        for key in s.daily_password_cnt:
            if key not in ctx.password_cnt:
                ctx.password_cnt[key] = 0
            ctx.password_cnt[key] += s.daily_password_cnt[key]
            
        for key in s.daily_ip_set_cnt:
            if key not in ctx.ip_set_cnt:
                ctx.ip_set_cnt[key] = 0
            ctx.ip_set_cnt[key] += s.daily_ip_set_cnt[key]

    ctx.password_cnt = sorted(ctx.password_cnt.items(), key=lambda item: item[1], reverse=True)
    ctx.username_cnt = sorted(ctx.username_cnt.items(), key=lambda item: item[1], reverse=True)

    return ctx

def get_geolocation(ip_list_cnt: dict):
    country_cnt = dict()
    orgs = dict()
    country_activity_cnt = dict()

    def get_ip_detail(ip: str):
        url = f'http://ipinfo.io/{ip}/json'
        response = urlopen(url)
        data = json.load(response)
        country, org = pycountry.countries.get(alpha_2=data['country']).name, data['org'] if 'org' in data else "Unknown Org"
        country_cnt[country] = country_cnt[country] + 1 if country in country_cnt else 1
        orgs[org] = orgs[org] + 1 if org in orgs else 1

        if country not in country_activity_cnt:
            country_activity_cnt[country] = 0
        country_activity_cnt[country] += ip_list_cnt[ip]

    for ip in ip_list_cnt.keys():
        get_ip_detail(ip)

    print(json.dumps(dict(sorted(country_cnt.items(), key=lambda item: item[1], reverse=True)), indent=4, sort_keys=False))
    print(json.dumps(dict(sorted(orgs.items(), key=lambda item: item[1], reverse=True)), indent=4, sort_keys=False))
    print(json.dumps(dict(sorted(country_activity_cnt.items(), key=lambda item: item[1], reverse=True)), indent=4, sort_keys=False))

def get_unexpected_data():
    # <header: dict<value: cnt>>
    data = dict()

    with open(HTTP_LOG_PATH) as f:
        lines = f.readlines()

        for line in lines:
            line_json = json.loads(line)

            # if the data is empty, skip
            if 'data' not in line_json:
                continue

            cur_data = line_json["data"]

            for key in cur_data:
                if key in IGNORED_HEADER_LIST:
                    continue

                if key not in data:
                    data[key] = dict()

                if cur_data[key] not in data[key]:
                    data[key][cur_data[key]] = 0
                data[key][cur_data[key]] += 1

    print(json.dumps(data, indent=4, sort_keys=True))

def gen_parsed_log(ignore_general_req: bool = False):
    new_log = list()

    with open(HTTP_LOG_PATH) as f:
        lines = f.readlines()
        REDUCED_KEY = ["dest_ip", "dest_port", "src_port", "protocol"]

        for line in lines:
            line_json = json.loads(line)

            # rm unnecessary key
            for rk in REDUCED_KEY:
                del line_json[rk]

            # rm unnecessary data
            if "data" in line_json:
                line_json["action"] = line_json["data"]["method"]
                for rk in IGNORED_HEADER_LIST:
                    if rk in line_json["data"]:
                        del line_json["data"][rk]

                # sync referrer
                if "Referer" in line_json["data"]:
                    line_json["data"]["uri"] = line_json["data"]["Referer"]
                    del line_json["data"]["Referer"]

            # fine-tune timestamp and IP
            # line_json["timestamp"] = line_json["timestamp"].split("T")[0]
            line_json["src_ip"] = line_json["src_ip"].split(":")[0]

            new_log.append(line_json)
    f.close()

    with open('tmp.log', 'w') as f:
        for line in new_log:

            if ignore_general_req:

                # if line only 3 keys [timestamp, src_ip, action], skip
                if ignore_general_req and set(["timestamp", "src_ip", "action"]).issuperset(set(line.keys())):
                    continue

                if "data" in line and len(line["data"].keys()) == 2 and "uri" in line["data"] and "method" in line["data"] and line["data"]["uri"] in ["/", "http://20.0.168.81"]:
                    continue

            f.write(json.dumps(line) + "\n")
    f.close()

def get_framework_context() -> FrameworkContext:
    ctx = FrameworkContext()
    with open(CORAZA_LOG_PATH) as f:
        # readline
        lines = f.readlines()

        for line in lines:

            # if line finds specific word "Violated"
            pattern = r':\s*\[([^\]]+)\]'

            match = re.findall(pattern, line)

            if match:
                for rule in str.split(match[0], " "):
                    ctx.rules[rule] = ctx.rules[rule] + 1 if rule in ctx.rules else 1

    keys = list(ctx.rules.keys())
    keys.sort()

    # sort mp with value
    mp = {k: v for k, v in sorted(ctx.rules.items(), key=lambda item: item[1], reverse=True)}
    # print(json.dumps(mp, indent=4, sort_keys=False))

    # RuleGroup
    rule_group = dict()

    for key in mp:
        new_key = key[0:3]
        rule_group[new_key] = mp[key] if new_key not in rule_group else rule_group[new_key] + mp[key]

    rule_group = {k: v for k, v in sorted(rule_group.items(), key=lambda item: item[1], reverse=True)}
    # print(json.dumps(rule_group, indent=4, sort_keys=False))
    return ctx

def get_malicious_ip_info():
    # read the file
    ip = dict()
    with open(MALICIOUS_INFO_PATH) as f:
        lines = f.readlines()
        for line in lines:
            cur_ip = line.split("-")[1][1:-1]
            ip[cur_ip] = ip[cur_ip] + 1 if cur_ip in ip else 1
    f.close()
    get_geolocation(ip)

if __name__ == "__main__":
    ctx = get_http_log_overview()
    framework_ctx = get_framework_context()

    # username/password frequency
    print(ctx.username_cnt)
    print(ctx.password_cnt)

    get_geolocation(ctx.ip_set_cnt)

    get_unexpected_data()

    get_framework_context()
    gen_parsed_log(ignore_general_req=True)

    # get malicious ip info
    get_malicious_ip_info()
    