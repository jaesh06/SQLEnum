"""Exercise real driver timeout behavior against a stalled local TCP peer."""

import socket
import multiprocessing
import time
import unittest

from collectors.mssql import MSSQLCollector
from collectors.mysql import MySQLCollector
from collectors.psql import PostgreSQLCollector
from scan_options import ScanOptions


def serve(socket, stop, accepted):
    while not stop.is_set():
        try:
            connection, _ = socket.accept()
        except TimeoutError:
            continue
        with connection:
            accepted.set()
            stop.wait(15)
        return


class StalledServer:
    def __enter__(self):
        self.socket = socket.socket()
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen()
        self.socket.settimeout(0.1)
        self.port = self.socket.getsockname()[1]
        # Native drivers can hold the GIL during connect; a process keeps the
        # test peer responsive independently of the client's extension module.
        context = multiprocessing.get_context('spawn')
        self.stop = context.Event()
        self.accepted = context.Event()
        self.process = context.Process(target=serve, args=(self.socket, self.stop, self.accepted), daemon=True)
        self.process.start()
        return self

    def __exit__(self, *args):
        self.stop.set()
        self.process.join(timeout=2)
        if self.process.is_alive():
            self.process.terminate()
            self.process.join(timeout=2)
        self.socket.close()


class TransportTimeoutTests(unittest.TestCase):
    def assert_timeout(self, cls, **kwargs):
        with StalledServer() as server:
            collector = cls('127.0.0.1', server.port, 'timeout_test', 'unused',
                            options=ScanOptions(connect_timeout=2, query_timeout=2), **kwargs)
            started = time.monotonic()
            try:
                with self.assertRaises(Exception):
                    collector.createConnection('app')
                self.assertTrue(server.accepted.is_set())
                self.assertLess(time.monotonic() - started, 12)
                self.assertIsNone(collector.connection)
            finally:
                collector.close()

    def test_postgres_stalled_connection(self):
        self.assert_timeout(PostgreSQLCollector)

    def test_mysql_stalled_connection(self):
        self.assert_timeout(MySQLCollector)

    def test_native_mssql_stalled_connection(self):
        self.assert_timeout(MSSQLCollector)

    def test_impacket_stalled_connection(self):
        self.assert_timeout(MSSQLCollector, domain='TEST')


if __name__ == '__main__':
    unittest.main()
