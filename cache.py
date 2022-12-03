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
        for record in self.cache[q_type][record_name][0]:
            reply.add_answer(self.get_pr_record(q_type, record_name, record[0], record[2]))

        if len(self.cache[q_type][record_name][1]) > 0:
            for record in self.cache[q_type][record_name][1]:
                reply.add_auth(self.get_pr_record(q_type, record_name, record[0], record[2]))

        if len(self.cache[q_type][record_name][2]) > 0:
            for record in self.cache[q_type][record_name][2]:
                reply.add_ar(self.get_pr_record(q_type, record_name, record[0], record[2]))

        return reply.pack()

    def get_pr_record(self, q_type, body, rec, time_tl):
        return RR(body, qtype_to_int[q_type][0], rdata=qtype_to_int[q_type][1](rec), ttl=time_tl)

    def add_rr_records(self, records):
        q_type = records[0].rtype
        q_name = str(records[0].rname)
        self.cache[q_type][q_name] = [[], [], []]
        res_list = []
        for record in records:
            print(record.ttl)
            res_list.append((str(record.rdata), time.time(), record.ttl))
        self.cache[q_type][q_name][0] = res_list

    def add_auth_records(self, records):
        if len(records) == 0:
            return
        res_list = []
        for record in records:
            print(record.ttl)
            res_list.append((str(record.rdata), time.time(), record.ttl))
        self.cache[records[0].rtype][str(records[0].rname)][1] = res_list

    def add_ar_records(self, records):
        if len(records) == 0:
            return
        res_list = []
        for record in records:
            print(record.ttl)
            res_list.append((str(record.rdata), time.time(), record.ttl))
        self.cache[records[0].rtype][str(records[0].rname)][2] = res_list

    def remove_expired_records(self):
        q_types = self.cache.keys()
        for q_type in q_types:
            q_names = self.cache[q_type].keys()
            list_to_del = []
            for q_name in q_names:
                for record_part in range(0, 3):
                    len_of_part = len(self.cache[q_type][q_name][record_part])
                    if len_of_part == 0:
                        continue
                    for res_rec in self.cache[q_type][q_name][record_part]:
                        time_record_created = res_rec[1]
                        ttl = res_rec[2]
                        if time.time() - time_record_created > ttl:
                            list_to_del.append(q_name)
                            break
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
