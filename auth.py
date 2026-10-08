#!/usr/bin/env python3
"""重庆师范大学校园网自动认证脚本（仅使用 Python 标准库）。"""

import argparse
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request


HOST = "10.0.254.125"
ENDPOINT = f"http://{HOST}:801/eportal/portal/login"
DEFAULT_CONFIG = Path(__file__).resolve().with_name("config.json")


class AuthError(Exception):
    """只携带可安全输出的错误信息。"""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # 不将含凭据的请求跟随重定向发送到其他地址。
        return None


def initialize(path):
    account = input("校园网账号：").strip()
    password = getpass.getpass("校园网密码（不显示）：")
    if not account or not password:
        raise AuthError("账号和密码不能为空。")
    try:
        # 原子拒绝覆盖已有配置；POSIX 上仅当前用户可读写。
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"account": account, "password": password, "user_ip": ""},
                      stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except FileExistsError:
        raise AuthError("配置已存在，请直接编辑本地配置文件。") from None
    except OSError:
        raise AuthError("无法写入配置，请检查目录和文件权限。") from None
    print("本地配置已创建。")


def load_config(path):
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise AuthError("无法读取配置，请先使用 --init 创建配置并检查 JSON 格式。") from None
    if not isinstance(config, dict):
        raise AuthError("配置必须是 JSON 对象。")
    for key in ("account", "password"):
        if not isinstance(config.get(key), str) or not config[key]:
            raise AuthError("请在本地配置中填写账号和密码。")
    if config["account"] == "YOUR_ACCOUNT" or config["password"] == "YOUR_PASSWORD":
        raise AuthError("请将示例配置中的占位符替换为自己的账号和密码。")
    user_ip = config.get("user_ip", "")
    if not isinstance(user_ip, str):
        raise AuthError("user_ip 必须是 IPv4 字符串或空字符串。")
    if user_ip:
        try:
            ipaddress.IPv4Address(user_ip)
        except ValueError:
            raise AuthError("user_ip 必须是有效的 IPv4 地址。") from None
    return config


def local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            # UDP connect 仅选择到认证服务器的本地路由，无需互联网。
            sock.connect((HOST, 801))
            return sock.getsockname()[0]
    except OSError:
        raise AuthError("无法确定校园网 IP，请连接校园网或在配置中填写 user_ip。") from None


def build_url(config):
    params = {
        "callback": "dr1005", "login_method": "1",
        "user_account": ",0," + config["account"],
        "user_password": config["password"],
        "wlan_user_ip": config.get("user_ip") or local_ip(),
        "wlan_user_ipv6": "", "wlan_user_mac": "000000000000",
        "wlan_ac_ip": "", "wlan_ac_name": "", "jsVersion": "4.1.3",
        "ua_name": "Netscape", "ua_version": "5.0",
        "ua_code": "Mozilla", "ua_agent": "Mozilla/5.0",
        "mac_type": "0", "wlan_type": "1", "lang": "zh-cn",
        "v": str(time.time_ns() % 10000),
    }
    return ENDPOINT + "?" + urllib.parse.urlencode(params)


def decode_response(body):
    text = body.strip()
    match = re.fullmatch(r"dr1005\s*\((.*)\)\s*;?", text, re.DOTALL)
    if match:
        text = match.group(1)
    try:
        data = json.loads(text)
    except ValueError:
        raise AuthError("认证服务器返回了无法识别的内容。") from None
    if not isinstance(data, dict):
        raise AuthError("认证服务器响应格式不正确。")
    return data


def response_for_display(body, config):
    """保留响应字段和消息，隐藏已知凭据；不显示无法解析的原文。"""
    try:
        data = decode_response(body)
    except AuthError:
        return "响应不是可识别的 JSON/JSONP，已省略原文。"
    text = json.dumps(data, ensure_ascii=False)
    secrets = set()
    for key in ("account", "password"):
        value = config[key]
        secrets.add(json.dumps(value, ensure_ascii=False)[1:-1])
        secrets.add(json.dumps(value, ensure_ascii=True)[1:-1])
        secrets.add(urllib.parse.quote(value, safe=""))
        secrets.add(urllib.parse.quote_plus(value, safe=""))
    for secret in sorted(secrets, key=len, reverse=True):
        if secret:
            text = re.sub(re.escape(secret), "[REDACTED]", text, flags=re.IGNORECASE)
    return text


def parse_response(body):
    data = decode_response(body)
    for key in ("msg", "message"):
        message = data.get(key)
        if isinstance(message, str):
            if message.strip().rstrip("！!") == "终端IP已在线":
                return "当前终端 IP 已在线，无需重复登录。"
            if "请勿重复登录" in message:
                return "当前已认证，无需重复登录。"
    if type(data.get("result")) in (int, str) and str(data["result"]) == "1":
        return "认证成功。"
    # 不输出服务器原文，其中可能回显账号或密码。
    raise AuthError("服务器未确认认证成功：请检查凭据、IP，或是否已经在线。")


def authenticate(config, show_response=False):
    request = urllib.request.Request(build_url(config), headers={
        "User-Agent": "Mozilla/5.0", "Referer": f"http://{HOST}/",
        "Accept": "*/*", "Accept-Encoding": "identity",
    })
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=10) as response:
            body = response.read(65537)
            if len(body) > 65536:
                raise AuthError("认证响应过大，已停止处理。")
            text = body.decode("utf-8")
            if show_response:
                print("服务器响应（已遮盖配置中的账号和密码）：" +
                      response_for_display(text, config), flush=True)
            return parse_response(text)
    except urllib.error.HTTPError as error:
        raise AuthError(f"认证服务器返回 HTTP {error.code}，请检查校园网连接。") from None
    except (urllib.error.URLError, OSError, UnicodeError, ValueError):
        raise AuthError("认证请求失败，请检查校园网连接、IP 和服务器状态。") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="本地配置路径")
    parser.add_argument("--init", action="store_true", help="交互创建配置，不覆盖已有文件")
    parser.add_argument("--watch", action="store_true", help="定期重新认证，掉线后自动重试")
    parser.add_argument("--show-response", action="store_true", help="显示服务器 JSON 响应，遮盖配置中的账号和密码")
    parser.add_argument("--interval", type=int, default=300, help="重试间隔（秒，至少 30，默认 300）")
    args = parser.parse_args()
    if args.interval < 30:
        parser.error("--interval 必须至少为 30 秒")
    try:
        if args.init:
            initialize(args.config)
            return 0
        config = load_config(args.config)
        while True:
            try:
                print(authenticate(config, show_response=args.show_response), flush=True)
                status = 0
            except AuthError as error:
                print(str(error), flush=True)
                status = 1
            if not args.watch:
                return status
            time.sleep(args.interval)
    except AuthError as error:
        print(str(error))
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\n已退出。")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
