import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from openpyxl import Workbook
import urllib3
from tqdm import tqdm
import socket
import ssl
import binascii
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def scan_target(ip, port):
    #1.灯塔系统
    try:
        url = f"https://{ip}:{port}"
        res = requests.get(url, verify=False, timeout=3)
        res.encoding = "utf-8"
        if "资产灯塔系统" in res.text:
            return {"ip": ip, "port": port, "title": "灯塔资产系统"}
    except:
        pass
    #2.Viper
    try:
        res = requests.get(f"https://{ip}:{port}/#/user/login", verify=False, timeout=3)
        res.encoding = "utf-8"
        if "VIPER" in res.text:
            return {"ip": ip, "port": port, "title": "Viper"}
    except:
        pass
    #3.AWVS
    try:
        res =requests.get(f"https://{ip}:{port}/#/user/login",verify=False,timeout=3)
        res.encoding="utf-8"
        if "<title>Acunetix</title>" in res.text:
            return {"ip": ip, "port": port, "title": "AWVS漏洞扫描器"}
    except:
        pass
    #4.大宝剑
    try:
        res =requests.get(f"http://{ip}:{port}/auth/login",verify=False,timeout=3)
        res.encoding="utf-8"
        if "大宝剑-实战化攻防对抗系统" in res.text:
            return {"ip": ip, "port": port, "title": "大宝剑-实战化攻防对抗系统"}
    except:
        pass
    #5.H(资产收集)
    try:
        res =requests.get(f"http://{ip}:{port}/login",verify=False,timeout=3)
        res.encoding="utf-8"
        if "Flask Datta Able" in res.text:
            return {"ip": ip, "port": port, "title": "H资产收集平台"}
    except:
        pass
    #6.LangSrc
    try:
        url = f"http://{ip}:{port}"
        res = requests.get(url, verify=False, timeout=3)
        res.encoding = "utf-8"
        if "LangSrc" in res.text:
            return {"ip": ip, "port": port, "title": "LangSrc(资产监控平台)"}
    except:
        pass
    #7.Manjusaka
    try:
        url = f"http://{ip}:{port}/manjusaka/static/#/login?redirect=/agents"
        res = requests.get(url, verify=False, timeout=3)
        res.encoding = "utf-8"
        if "Manjusaka" in res.text:
            return {"ip": ip, "port": port, "title": "Manjusaka(牛屎花C2管理)"}
    except:
        pass
    #8.美杜莎红队武器库平台
    try:
        url = f"https://{ip}:{port}/#/user/login"
        res = requests.get(url, verify=False, timeout=3)
        res.encoding = "utf-8"
        if "Medusa doesn't work properly without JavaScript" in res.text:
            return {"ip": ip, "port": port, "title": "美杜莎红队武器库平台"}
    except:
        pass
    #9.nemo
    try:
        url = f"http://{ip}:{port}/"
        res = requests.get(url, verify=False, timeout=3)
        res.encoding = "utf-8"
        if "Nemo" in res.text:
            return {"ip": ip, "port": port, "title": "nemo(自动化信息收集)"}
    except:
        pass
    #10.Nessus
    try:
        url = f"https://{ip}:{port}/#/"
        res = requests.get(url, verify=False, timeout=3)
        res.encoding = "utf-8"
        if "Nessus" in res.text:
            return {"ip": ip, "port": port, "title": "Nessus(漏洞扫描器)"}
    except:
        pass
    #11.NextScan
    try:
        url = f"http://{ip}:{port}/"
        res = requests.get(url, verify=False, timeout=3)
        res.encoding = "utf-8"
        if "NextScan" in res.text:
            return {"ip": ip, "port": port, "title": "NextScan(黑盒扫描)"}
    except:
        pass
    #12.NPS
    try:
        url = f"http://{ip}:{port}/login/index"
        res = requests.get(url, verify=False, timeout=3)
        res.encoding = "utf-8"
        if "nps" in res.text:
            print(f"{url} ---- NPS(穿透工具)")
            return {"ip": ip, "port": port, "title": "NPS(穿透工具)"}
    except:
        pass
    #12.NPS
    try:
        url = f"http://{ip}:{port}/login/index"
        res = requests.get(url, verify=False, timeout=3)
        res.encoding = "utf-8"
        if '<a href="https://ehang.io/nps"' in res.text:
            print(f"{url} ---- NPS(穿透工具)")
            return {"ip": ip, "port": port, "title": "NPS(穿透工具)"}
    except:
        pass
    #13.Frp web
    try:
        url = f"http://{ip}:{port}/"
        res = requests.get(url, verify=False, timeout=3)
        res.encoding = "utf-8"
        if "frp " in res.text:
            return {"ip": ip, "port": port, "title": "Frp面板"}
    except:
        pass

    #14.DNSLOG平台
    try:
        url = f"http://{ip}:{port}/"
        res = requests.get(url, verify=False, timeout=3)
        res.encoding = "utf-8"
        if "dnslog" in res.text:
            return {"ip": ip, "port": port, "title": "DNSLOG平台"}
    except:
        pass
    #15.supershell平台
    try:
        url = f"http://{ip}:{port}/supershell/login"
        res = requests.get(url, verify=False, timeout=3)
        res.encoding = "utf-8"
        if "Supershell" in res.text:
            return {"ip": ip, "port": port, "title": "Supershell-c2"}
    except:
        pass
    #15.xray Cland Beta 反连平台
    try:
        url = f"http://{ip}:{port}/cland/"
        res = requests.get(url, verify=False, timeout=3)
        res.encoding = "utf-8"
        if "cland" in res.text:
            return {"ip": ip, "port": port, "title": "xray Cland Beta 反连平台"}
    except:
        pass
def scan_ports(ip, ports):
    results = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(scan_target, ip, port) for port in ports]
        for future in tqdm(as_completed(futures), total=len(ports), desc=f"疯狂加载中(o|o) ", colour='green', ncols=100):
            result = future.result()
            if result:
                results.append(result)
    return results


def scan_all_ports(ip):
    all_ports = list(range(1, 65536))
    return scan_ports(ip, all_ports)


def main():
    banner = """      
     _    ______  _____    ______                __            
    | |  / / __ \/ ___/   /_  __/________ ______/ /_____  _____
    | | / / /_/ /\__ \     / / / ___/ __ `/ ___/ //_/ _ \/ ___/
    | |/ / ____/___/ /    / / / /  / /_/ / /__/ ,< /  __/ /    
    |___/_/    /____/    /_/ /_/   \__,_/\___/_/|_|\___/_/    
                                                        Version:1.0
                                                        Author: GeniusZJL
                                                        公众号：Sec探索者
        python3 VPS_Tracker.py -t 127.0.0.1 #检测单个IP
        python3 VPS_Tracker.py -f url.txt   #批量多个IP        
        python3 VPS_Tracker.py -t 127.0.0.1 -all #单个IP全端口扫描
        python3 VPS_Tracker.py -f url.txt -all #多个IP全端口扫描
            """
    print(banner)
    parser = argparse.ArgumentParser(description="vps_tracker")
    parser.add_argument("-t", "--target", dest="target_ip", help="主机IP")
    parser.add_argument("-f", "--file", dest="file_path", help="IP地址文件")
    parser.add_argument("-all", "--all-ports", action="store_true", help="扫描所有端口")
    args = parser.parse_args()

    if not (args.target_ip or args.file_path):
        parser.error("At least one of -t or -f must be provided.")

    ports_to_scan = [80, 443, 8080, 22, 3389, 5003, 8888, 3443, 5000, 6000, 7000, 7500, 8081, 5005, 3200, 8001, 8834, 8082, 8083, 8084, 8085, 60000, 50050,8777]

    results = []

    if args.file_path:
        with open(args.file_path, "r") as file:
            target_ips = [line.strip() for line in file if line.strip()]
    elif args.target_ip:
        target_ips = [args.target_ip]

    for target_ip in target_ips:
        print(f"疯狂扫描 {target_ip} ")
        if args.all_ports:
            target_results = scan_all_ports(target_ip)
        else:
            target_results = scan_ports(target_ip, ports_to_scan)
        results.extend(target_results)

    if results:
        workbook = Workbook()
        sheet = workbook.active
        sheet.append(["IP", "Port", "Title"])
        for result in results:
            sheet.append([result["ip"], result["port"], result["title"]])
        workbook.save("result.xlsx")
        print("成功逮到黑客(￣3￣)")
    else:
        print("没有逮到黑客(－O－)")

if __name__ == "__main__":
    main()