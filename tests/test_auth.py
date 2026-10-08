import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse

import auth


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.config = {"account": "demo-user", "password": "dummy!&+=中文",
                       "user_ip": "10.1.2.3"}

    def test_credentials_and_special_characters_round_trip(self):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(auth.build_url(self.config)).query)
        self.assertEqual(query["user_account"], [",0,demo-user"])
        self.assertEqual(query["user_password"], [self.config["password"]])
        self.assertEqual(query["wlan_user_ip"], ["10.1.2.3"])

    def test_detects_ip_when_not_configured(self):
        self.config["user_ip"] = ""
        with patch("auth.local_ip", return_value="10.9.8.7"):
            self.assertIn("wlan_user_ip=10.9.8.7", auth.build_url(self.config))

    def test_success_response_formats(self):
        for body in ('{"result":1}', 'dr1005({"result":"1"});'):
            self.assertEqual(auth.parse_response(body), "认证成功。")

    def test_already_online_response_formats(self):
        for key in ("msg", "message"):
            for escaped in (True, False):
                payload = json.dumps({"result": 0, key: "请勿重复登录！"},
                                     ensure_ascii=escaped)
                for body in (payload, f"dr1005({payload});"):
                    with self.subTest(key=key, escaped=escaped, body=body):
                        self.assertEqual(auth.parse_response(body), "当前已认证，无需重复登录。")

    def test_invalid_message_values_are_not_online(self):
        for value in (None, 123, ["请勿重复登录"], {"text": "请勿重复登录"}):
            with self.subTest(value=value), self.assertRaises(auth.AuthError):
                auth.parse_response(json.dumps({"result": 0, "msg": value}))

    def test_already_online_cli_succeeds_without_echoing_credentials(self):
        payload = json.dumps({"result": 0, "msg": "请勿重复登录：" + self.config["password"]})
        output = io.StringIO()
        with patch("sys.argv", ["auth.py"]), \
             patch("auth.load_config", return_value=self.config), \
             patch("auth.urllib.request.build_opener") as build, \
             contextlib.redirect_stdout(output):
            build.return_value.open.return_value.__enter__.return_value.read.return_value = payload.encode()
            self.assertEqual(auth.main(), 0)
        self.assertEqual(output.getvalue(), "当前已认证，无需重复登录。\n")

    def test_watch_continues_after_already_online(self):
        output = io.StringIO()
        with patch("sys.argv", ["auth.py", "--watch"]), \
             patch("auth.load_config", return_value=self.config), \
             patch("auth.authenticate", side_effect=["当前已认证，无需重复登录。", "认证成功。"]) as login, \
             patch("auth.time.sleep", side_effect=[None, KeyboardInterrupt]) as sleep, \
             contextlib.redirect_stdout(output):
            self.assertEqual(auth.main(), 0)
        self.assertEqual(login.call_count, 2)
        self.assertEqual(sleep.call_count, 2)
        self.assertIn("当前已认证，无需重复登录。\n认证成功。", output.getvalue())

    def test_http_ok_is_not_authentication_success(self):
        for body in ('<html>login</html>', '{}', '[]', '{"result":0}',
                     '{"result":true}', 'other({"result":1});'):
            with self.subTest(body=body), self.assertRaises(auth.AuthError):
                auth.parse_response(body)

    def test_server_errors_do_not_echo_private_content(self):
        with self.assertRaises(auth.AuthError) as caught:
            auth.parse_response(json.dumps({"result": 0, "msg": self.config["password"]}))
        self.assertNotIn(self.config["password"], str(caught.exception))

    def test_network_errors_do_not_leak_url(self):
        with patch("auth.urllib.request.build_opener") as build:
            build.return_value.open.side_effect = urllib.error.URLError(auth.build_url(self.config))
            with self.assertRaises(auth.AuthError) as caught:
                auth.authenticate(self.config)
        self.assertNotIn("user_password", str(caught.exception))
        self.assertNotIn("demo-user", str(caught.exception))

    def test_redirect_is_refused(self):
        self.assertIsNone(auth.NoRedirect().redirect_request(None, None, 302, "", {},
                                                            "http://example.com/"))

    def test_initialization_does_not_overwrite_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text("existing", encoding="utf-8")
            with patch("builtins.input", return_value="demo"), \
                 patch("getpass.getpass", return_value="dummy"), \
                 self.assertRaises(auth.AuthError):
                auth.initialize(path)
            self.assertEqual(path.read_text(), "existing")

    def test_invalid_config_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            for value in ([], {}, {**self.config, "user_ip": "invalid"}):
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(auth.AuthError):
                    auth.load_config(path)


if __name__ == "__main__":
    unittest.main()
