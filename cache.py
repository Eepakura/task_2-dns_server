import pickle
import time
from dnslib import A, NS, QTYPE, RR

qtype_to_int = {1: (QTYPE.A, A),
                2: (QTYPE.NS, NS)}


class Cache:
    TIME_CACHE_CLEANED = time.time()

    def __init__(self):
        self.cache = {}
        for record_type in qtype_to_int.keys():
            self.cache[record_type] = {}

    def get_record(self, parsed_packet):
        record_name = str(parsed_packet.q.qname)
        q_type = parsed_packet.q.qtype
        if q_type not in self.cache or record_name not in self.cache[q_type]:
            return
        reply = parsed_packet.reply()
        for record in self.cache[q_type][record_name]:
            reply.add_answer(self.get_pr_record(q_type, record_name, record[0]))
        return reply.pack()

    def get_pr_record(self, q_type, body, rec):
        return RR(body, qtype_to_int[q_type][0], rdata=qtype_to_int[q_type][1](rec), ttl=180)

    def add_records(self, records):
        for record in records:
            self.cache[record.rtype][str(record.rname)] = []
        for record in records:
                self.cache[record.rtype][str(record.rname)].append((str(record.rdata), time.time(), 180))

    def remove_expired_records(self):
        for q_type in self.cache:
            list_to_del = []
            for q_name in self.cache[q_type]:
                time_record_created = self.cache[q_type][q_name][0][1]
                ttl = self.cache[q_type][q_name][0][2]
                if time.time() - time_record_created > ttl:
                    list_to_del.append(q_name)
            for q_name in list_to_del:
                del self.cache[q_type][q_name]
        self.TIME_CACHE_CLEANED = time.time()

    def save_cache(self, cache_file_name):
        with open(cache_file_name, 'wb+') as dump:
            pickle.dump(self, dump)

    @staticmethod
    def load_cache(cache_file_name):
        try:
            with open(cache_file_name, 'rb') as dump:
                cache = pickle.load(dump)
            print('Cache loaded')
            return cache
        except FileNotFoundError:
            print('Cache created')
            return Cache()
        except EOFError:
            print('Cache is empty')
            return Cache()
