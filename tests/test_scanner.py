#!/usr/bin/env python3
"""
Unit tests for Labmentix Port Scanner Tool.
Tests port range parsing, target resolution, socket scanning against mock listeners,
banner grabbing, and report export logic.
"""

import os
import socket
import tempfile
import threading
import time
import unittest

from port_scanner import PortScanner, parse_port_range, TOP_20_PORTS, TOP_100_PORTS


class MockTcpServer:
    """Helper thread to run a temporary mock TCP service with a known banner."""

    def __init__(self, host: str = "127.0.0.1", banner: str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"):
        self.host = host
        self.banner = banner.encode("utf-8")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(5)
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while self.running:
            try:
                self.sock.settimeout(0.5)
                client, _ = self.sock.accept()
                client.sendall(self.banner)
                # Give client time to read before close
                time.sleep(0.1)
                client.close()
            except socket.timeout:
                continue
            except Exception:
                break

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass
        self.thread.join(timeout=1.0)


class TestPortScanner(unittest.TestCase):

    def test_parse_port_range_presets(self):
        self.assertEqual(parse_port_range("top20"), TOP_20_PORTS)
        self.assertEqual(parse_port_range("top100"), TOP_100_PORTS)

    def test_parse_port_range_single_and_list(self):
        self.assertEqual(parse_port_range("80"), [80])
        self.assertEqual(parse_port_range("80, 443, 22"), [22, 80, 443])

    def test_parse_port_range_hyphen_range(self):
        self.assertEqual(parse_port_range("80-83"), [80, 81, 82, 83])
        self.assertEqual(parse_port_range("22, 80-82"), [22, 80, 81, 82])

    def test_parse_port_range_invalid(self):
        with self.assertRaises(ValueError):
            parse_port_range("0")
        with self.assertRaises(ValueError):
            parse_port_range("70000")
        with self.assertRaises(ValueError):
            parse_port_range("100-50")
        with self.assertRaises(ValueError):
            parse_port_range("abc")

    def test_target_resolution(self):
        scanner = PortScanner(target="127.0.0.1", ports=[80], scan_type="T")
        self.assertEqual(scanner.ip_address, "127.0.0.1")

    def test_scan_open_and_closed_ports(self):
        # Start mock server
        mock = MockTcpServer(banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        open_port = mock.port

        # Choose a closed port (find an unused port)
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_sock.bind(("127.0.0.1", 0))
        closed_port = temp_sock.getsockname()[1]
        temp_sock.close()

        try:
            scanner = PortScanner(
                target="127.0.0.1",
                ports=[open_port, closed_port],
                scan_type="T",
                timeout=0.5,
                service_detect=True
            )
            results = scanner.run_scan()

            open_res = next((r for r in results if r.port == open_port), None)
            closed_res = next((r for r in results if r.port == closed_port), None)

            self.assertIsNotNone(open_res)
            self.assertEqual(open_res.state, "open")
            self.assertIn("OpenSSH", open_res.service)
            self.assertIn("SSH-2.0", open_res.banner)

            self.assertIsNotNone(closed_res)
            self.assertEqual(closed_res.state, "closed")

            summary = scanner.get_summary()
            self.assertEqual(summary["total_ports"], 2)
            self.assertEqual(summary["open_ports"], 1)
            self.assertEqual(summary["closed_ports"], 1)
        finally:
            mock.stop()

    def test_exports(self):
        scanner = PortScanner(target="127.0.0.1", ports=[9], scan_type="T", timeout=0.1)
        scanner.run_scan()

        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, "out.json")
            csv_path = os.path.join(tmpdir, "out.csv")
            txt_path = os.path.join(tmpdir, "out.txt")

            scanner.export_json(json_path)
            scanner.export_csv(csv_path)
            scanner.export_text(txt_path)

            self.assertTrue(os.path.exists(json_path))
            self.assertTrue(os.path.exists(csv_path))
            self.assertTrue(os.path.exists(txt_path))

            # Verify JSON content is valid
            with open(json_path, "r", encoding="utf-8") as f:
                import json
                data = json.load(f)
                self.assertIn("metadata", data)
                self.assertIn("ports", data)


if __name__ == "__main__":
    unittest.main()
