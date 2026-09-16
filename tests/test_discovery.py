import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from unittest.mock import patch

from pve_service_discovery import (
    ContainerOverride,
    END_MARKER,
    START_MARKER,
    Container,
    MarkerError,
    Settings,
    Service,
    build_managed_block,
    extract_title,
    merge_managed_block,
    parse_proc_net_tcp,
    parse_ss_ports,
    probe_endpoint,
    remove_managed_block,
    set_description,
)


class ParsingTests(unittest.TestCase):
    def test_parse_ss_ports(self):
        output = """\
LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*
LISTEN 0 511 [::]:8090 [::]:*
LISTEN 0 128 127.0.0.1:3000 0.0.0.0:*
"""
        self.assertEqual(parse_ss_ports(output), {22, 3000, 8090})

    def test_parse_proc_tcp(self):
        output = """\
  sl  local_address rem_address   st tx_queue rx_queue
   0: 00000000:1F9A 00000000:0000 0A 00000000:00000000
   1: 0100007F:0BB8 00000000:0000 01 00000000:00000000
"""
        self.assertEqual(parse_proc_net_tcp(output), {8090})

    def test_extract_title(self):
        body = b"<html><head><title> Beszel &amp; Friends </title></head></html>"
        self.assertEqual(extract_title(body, "text/html; charset=utf-8"), "Beszel & Friends")

    def test_set_description_uses_proxmox_digest(self):
        with patch("pve_service_discovery.run_command") as command:
            set_description("proxmox", 105, "new notes", "abc123")
        command.assert_called_once_with(
            [
                "pvesh",
                "set",
                "/nodes/proxmox/lxc/105/config",
                "--description",
                "new notes",
                "--digest",
                "abc123",
            ]
        )


class ProbeTests(unittest.TestCase):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html><head><title>Test Appliance</title></head></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    def test_local_http_service_probe(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), self.Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            services = probe_endpoint(
                "127.0.0.1",
                server.server_port,
                "test-ct",
                Settings(timeout=1.0),
                ContainerOverride(),
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertEqual(len(services), 1)
        service = services[0]
        self.assertEqual(service.title, "Test Appliance")
        self.assertEqual(service.scheme, "http")
        self.assertEqual(service.status, 200)

    def test_discovers_guacamole_subpath_from_container_name(self):
        class GuacamoleHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/guacamole/":
                    body = b"<html><title>Apache Guacamole</title></html>"
                    self.send_response(200)
                else:
                    body = b"<html><title>HTTP Status 404 - Not Found</title></html>"
                    self.send_response(404)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), GuacamoleHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            services = probe_endpoint(
                "127.0.0.1",
                server.server_port,
                "apache-guacamole",
                Settings(timeout=1.0),
                ContainerOverride(),
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertEqual(len(services), 1)
        service = services[0]
        self.assertEqual(service.title, "Apache Guacamole")
        self.assertTrue(service.url.endswith("/guacamole/"))
        self.assertEqual(service.status, 200)

    def test_lists_distinct_titleless_200_root_and_app_path(self):
        class TitlelessGuacamoleHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/guacamole/":
                    body = b"<html><script src='guacamole.js'></script></html>"
                else:
                    body = b"<html><body>Web server is running</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html;charset=UTF-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), TitlelessGuacamoleHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            services = probe_endpoint(
                "127.0.0.1",
                server.server_port,
                "apache-guacamole",
                Settings(timeout=1.0),
                ContainerOverride(),
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertEqual(len(services), 2)
        self.assertEqual(
            {service.url.rsplit(":", 1)[-1].split("/", 1)[-1] for service in services},
            {"", "guacamole/"},
        )
        self.assertTrue(all(service.status == 200 for service in services))

    def test_lists_distinct_titleless_206_root_and_app_path(self):
        class PartialContentHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/guacamole/":
                    body = b"<html><script src='guacamole.js'></script></html>"
                else:
                    body = b"<html><body>Web server is running</body></html>"
                self.send_response(206)
                self.send_header("Content-Type", "text/html;charset=UTF-8")
                self.send_header("Content-Range", f"bytes 0-{len(body) - 1}/{len(body)}")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), PartialContentHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            services = probe_endpoint(
                "127.0.0.1",
                server.server_port,
                "apache-guacamole",
                Settings(timeout=1.0),
                ContainerOverride(),
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertEqual(len(services), 2)
        self.assertTrue(any(service.url.endswith("/guacamole/") for service in services))
        self.assertTrue(all(service.status == 206 for service in services))

    def test_identical_catch_all_page_keeps_root_url(self):
        class CatchAllHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"<html><body>Single-page application</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), CatchAllHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            services = probe_endpoint(
                "127.0.0.1",
                server.server_port,
                "some-application",
                Settings(timeout=1.0),
                ContainerOverride(),
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertEqual(len(services), 1)
        service = services[0]
        self.assertTrue(service.url.endswith("/"))
        self.assertFalse(service.url.endswith("/application/"))


class NotesTests(unittest.TestCase):
    def setUp(self):
        self.container = Container(105, "beszel", "running")
        self.service = Service(
            "192.168.1.87", 8090, "http", "http://192.168.1.87:8090/", "Beszel", 200
        )
        self.block = build_managed_block(
            self.container, ["192.168.1.87"], [self.service]
        )

    def test_append_preserves_manual_notes(self):
        original = "GPU monitor\nDo not upgrade past driver 535."
        merged = merge_managed_block(original, self.block)
        self.assertTrue(merged.startswith(original + "\n\n"))
        self.assertIn("[Beszel](http://192.168.1.87:8090/)", merged)

    def test_second_merge_is_idempotent(self):
        once = merge_managed_block("Manual", self.block)
        twice = merge_managed_block(once, self.block)
        self.assertEqual(once, twice)

    def test_replace_only_managed_block(self):
        old = f"Before\n\n{START_MARKER}\nold\n{END_MARKER}\n\nAfter"
        merged = merge_managed_block(old, self.block)
        self.assertTrue(merged.startswith("Before\n\n"))
        self.assertTrue(merged.endswith("\n\nAfter"))
        self.assertNotIn("\nold\n", merged)

    def test_unbalanced_markers_refuse_update(self):
        with self.assertRaises(MarkerError):
            merge_managed_block(f"manual\n{START_MARKER}\n", self.block)

    def test_remove_preserves_both_sides(self):
        old = f"Before\n\n{self.block}\n\nAfter"
        self.assertEqual(remove_managed_block(old), "Before\n\nAfter")

    def test_duplicate_titles_are_disambiguated_by_path(self):
        services = [
            Service("192.168.1.50", 8080, "http", "http://192.168.1.50:8080/", "Guacamole", 200),
            Service(
                "192.168.1.50",
                8080,
                "http",
                "http://192.168.1.50:8080/guacamole/",
                "Guacamole",
                200,
            ),
        ]
        block = build_managed_block(self.container, ["192.168.1.50"], services)
        self.assertIn("[Guacamole — http /]", block)
        self.assertIn("[Guacamole — http /guacamole/]", block)


if __name__ == "__main__":
    unittest.main()
