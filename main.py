import time

import dnslib
import socket
from cache import Cache

public_dns = "8.8.8.8"
cache_update_periodicity = 180
cache_filename = "cache.txt"
localhost = "127.0.0.1"
port = 53
query_type_to_int = {1: (dnslib.QTYPE.A, dnslib.A),
                     2: (dnslib.QTYPE.NS, dnslib.NS)}


class Server:
    def __init__(self, cache):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind((localhost, port))
        self.cache = cache

    def run(self):
        while True:
            data, client_address = self.get_packet()
            self.clearing_cache(time.time())
            response = self.process_packet(data)
            self.server.sendto(response, client_address)

    def clearing_cache(self, time_now):
        if time_now - self.cache.TIME_CACHE_CLEANED > cache_update_periodicity:
            self.cache.remove_expired_records()

    def get_packet(self):
        try:
            self.server.recvfrom(1024)
            self.server.recvfrom(1024)
            return self.server.recvfrom(1024)
        except socket.timeout:
            return self.get_packet()
        except Exception as e:
            self.server.close()
            print(e)
            exit()

    def process_packet(self, package: bytes) -> bytes:
        byte_response = None
        response = None
        while response is None or len(response.rr) == 0:
            parsed_packet = dnslib.DNSRecord.parse(package)
            cache_record = self.cache.get_record(parsed_packet)
            if cache_record:
                print("Response from cache")
                return cache_record
            try:
                byte_response = parsed_packet.send(public_dns, timeout=5)
            except socket.timeout:
                print("Timeout error")
                continue
            response = dnslib.DNSRecord.parse(byte_response)

        self.cache.add_records(response.rr)
        print("Response from public dns")
        return byte_response


def main():
    cache = Cache.load_cache(cache_filename)
    try:
        Server(cache).run()
    except (KeyboardInterrupt, SystemExit):
        cache.save_cache(cache_filename)
        print("Cache saved")


if __name__ == '__main__':
    main()
