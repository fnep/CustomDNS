__author__ = 'Frank Epperlein'

import socket
import logging
from threading import Thread


DNS_RECORD_CLASSES = {
    1: 'IN',
    3: 'CH',
    4: 'HD',
    254: 'None',
    255: 'Any'
}

DNS_RECORD_TYPES = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    12: 'PTR',
    15: 'MX',
    16: 'TXT',
    17: 'RP',
    18: 'AFSDB',
    24: 'SIG',
    25: 'KEY',
    28: 'AAAA',
    29: 'LOC',
    33: 'SRV',
    35: 'NAPTR',
    36: 'KX',
    37: 'CERT',
    39: 'DNAME',
    42: 'APL',
    43: 'DS',
    44: 'SSHFP',
    45: 'IPSECKEY',
    46: 'RRSIG',
    47: 'NSEC',
    48: 'DNSKEY',
    49: 'DHCID',
    50: 'NSEC3',
    51: 'NSEC3PARAM',
    52: 'TLSA',
    55: 'HIP',
    99: 'SPF',
    249: 'TKEY',
    250: 'TSIG',
    257: 'CAA',
    32768: 'TA',
    32769: 'DLV'
}

DNS_RCODES = {
    0: "NoError",    # No Error
    1: "FormErr",    # Format Error
    2: "ServFail",   # Server Failure
    3: "NXDomain",   # Non-Existent Domain
    4: "NotImp",     # Not Implemented
    5: "Refused",    # Query Refused
    6: "YXDomain",   # Name Exists when it should not
    7: "YXRRSet",    # RR Set Exists when it should not
    8: "NXRRSet",    # RR Set that should exist does not
    9: "NotAuth",    # Server Not Authoritative for zone
    10: "NotZone",   # Name not contained in zone
    16: "BADVERS",   # Bad OPT Version
    17: "BADKEY",    # Key not recognized
    18: "BADTIME",   # Signature out of time window
    19: "BADMODE",   # Bad TKEY Mode
    20: "BADNAME",   # Duplicate key name
    21: "BADALG"     # Algorithm not supported
}


def pprint_data(data):
    # debug generated package
    print "##  DEZ   HEX        BIN"
    for index, byte in enumerate(bytearray(data)):
        print '%02d: %3s %5s %10s %s' % (index, byte, hex(byte), bin(byte), chr(byte))
    print ""


class DNSQueryResourceRecord(object):

    # rfc2929 DNS Resource Records
    #
    #                                  1  1  1  1  1  1
    #    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #  |                                               |
    #  /                                               /
    #  /                      NAME                     /
    #  |                                               |
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #  |                      TYPE                     |
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #  |                     CLASS                     |
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #  |                      TTL                      |
    #  |                                               |
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    #  |                   RDLENGTH                    |
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    #  /                     RDATA                     /
    #  /                                               /
    #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    def name(self):
        return self.record_name

    def type_name(self, number=False):
        return DNS_RECORD_TYPES.get(number or self.record_type, "")

    def class_name(self, number=False):
        return DNS_RECORD_CLASSES.get(number or self.record_class, "")

    @staticmethod
    def type_id(name):
        return dict(map(lambda k: (DNS_RECORD_TYPES[k], k), DNS_RECORD_TYPES)).get(name, 0)

    @staticmethod
    def class_id(name):
        return dict(map(lambda k: (DNS_RECORD_CLASSES[k], k), DNS_RECORD_CLASSES)).get(name, 0)

    @staticmethod
    def __portion(data, offset=0):
        return data[offset:data[offset:].index('\x00') + offset]

    @staticmethod
    def __get_name(data):
        domain_parts = []
        while len(data):
            part_length = ord(data[0])
            part_data = data[1:part_length + 1]
            domain_parts.append(part_data)
            data = data[part_length + 1:]

        return '.'.join(domain_parts)

    def __init__(self, data):
        name_portion = self.__portion(data, offset=0)
        name_len = len(name_portion)

        self.record_name = self.__get_name(name_portion)
        self.record_type = (ord(data[name_len + 1]) << 8) + ord(data[name_len + 2])
        self.record_class = (ord(data[name_len + 3]) << 8) + ord(data[name_len + 4])


class DNSRequest(object):

    def __init__(self, data, connection, lookup):
        assert isinstance(connection, GenericConnection)
        self.lookup = lookup
        self.connection = connection
        self.data = data

        # rfc2929 DNS Query/Response Header
        #
        #                                 1  1  1  1  1  1
        #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #  |                      ID                       |
        #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #  |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
        #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #  |                QDCOUNT/ZOCOUNT                |
        #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #  |                ANCOUNT/PRCOUNT                |
        #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #  |                NSCOUNT/UPCOUNT                |
        #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #  |                    ARCOUNT                    |
        #  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        #pprint_data(data)

        self.flags = dict(bytes=bytearray(data[0:12]))

        self.flags['ID'] = (ord(self.data[0]) << 8) + ord(self.data[1])

                                                     # 87654321
        self.flags['QR'] = (self.flags['bytes'][2] & 0b10000000) >> 7  # 0 = Query, 1 = Response
        self.flags['OP'] = (self.flags['bytes'][2] & 0b01111000) >> 3  # 0000 (0) = standard query, 0001 (1) = Inverse
        self.flags['AA'] = (self.flags['bytes'][2] & 0b00000100) >> 2  # 0 = non-authoritative, 1 = authoritative
        self.flags['TC'] = (self.flags['bytes'][2] & 0b00000010) >> 1  # 0 = message not truncated, 1 = truncated
        self.flags['RD'] = (self.flags['bytes'][2] & 0b00000001) >> 0  # 0 = non recursive query, 1 = recursive query
        self.flags['RA'] = (self.flags['bytes'][3] & 0b10000000) >> 7  # 0 = recursion not available, 1 = available
                                    # ['bytes'][3] & 0b01110000 needs to be zero
        self.flags['RCODE'] = (self.flags['bytes'][3] & 0b00001111) >> 0  # 0 = no error, 3 = name error

        self.flags['QDCOUNT'] = (ord(self.data[4]) << 8) + ord(self.data[5])
        self.flags['ANCOUNT'] = (ord(self.data[6]) << 8) + ord(self.data[7])
        self.flags['NSCOUNT'] = (ord(self.data[8]) << 8) + ord(self.data[8])
        self.flags['ARCOUNT'] = (ord(self.data[10]) << 8) + ord(self.data[11])

        # data byte 12 ++ is resource record
        self.record = DNSQueryResourceRecord(self.data[12:])

    def response(self):
        response = DNSResponse(self)
        self.lookup(self, response)
        return response.generate().buffer()


class DNSResponsePackage(list):

    def __init__(self):
        super(DNSResponsePackage, self).__init__()
        self.names = dict()

    @staticmethod
    def encode_name(name):
        encoded_name = str()
        for part in name.split('.'):
            encoded_name += chr(len(part))
            for char in part:
                encoded_name += char
        encoded_name += '\x00'
        return encoded_name

    def append_name(self, name):
        if name in self.names:
            # if the name is already somewhere in the package, just add a pointer
            self.append('\xc0')
            self.append(self.names[name])
        else:
            # store the position of the name for reuse
            self.names[name] = len(self)
            for char in self.encode_name(name):
                self.append(char)

    def append(self, p_object):
        if isinstance(p_object, str):
            p_object = ord(p_object)
        assert isinstance(p_object, int)
        super(DNSResponsePackage, self).append(p_object)

    def buffer(self):
        return buffer(''.join(map(lambda value: chr(value), self)))


class DNSResponse(object):

    def rcode_name(self, number=False):
        return DNS_RCODES.get(number or self.request.flags['RCODE'], "")

    @staticmethod
    def rcode_id(name):
        return dict(map(lambda k: (DNS_RCODES[k].lower(), k), DNS_RCODES)).get(name.lower(), 0)

    def __append_header(self, package, flags=False):

        assert isinstance(package, DNSResponsePackage)
        response_flags = self.request.flags.copy()
        response_flags['QR'] = 1  # is response
        response_flags['RD'] = 1  # is recursive query
        response_flags['RA'] = 1  # recursion is available
        response_flags['RCODE'] = self.__rcode or 0

        if flags:
            assert isinstance(flags, dict)
            response_flags.update(flags)

        # ID
        package.append(chr((response_flags['ID'] >> 8) & 0xFF))
        package.append(chr((response_flags['ID'] >> 0) & 0xFF))

        # Flags
        flag_bytes = [0, 0]
        flag_bytes[0] |= (response_flags['QR'] << 7)
        flag_bytes[0] |= (response_flags['OP'] << 3)
        flag_bytes[0] |= (response_flags['AA'] << 2)
        flag_bytes[0] |= (response_flags['TC'] << 1)
        flag_bytes[0] |= (response_flags['RD'] << 0)
        flag_bytes[1] |= (response_flags['RA'] << 7)
        flag_bytes[1] |= (response_flags['RCODE'] << 0)
        package.append(flag_bytes[0])
        package.append(flag_bytes[1])

        # QDCOUNT
        package.append(chr((response_flags['QDCOUNT'] >> 8) & 0xFF))
        package.append(chr((response_flags['QDCOUNT'] >> 0) & 0xFF))

        # ANCOUNT
        answer_count = len(self.__answers) or response_flags['ANCOUNT']
        package.append(chr((answer_count >> 8) & 0xFF))
        package.append(chr((answer_count >> 0) & 0xFF))

        # NSCOUNT
        package.append(0b00000000)
        package.append(0b00000000)

        # ARCOUNT
        package.append(0b00000000)
        package.append(0b00000000)

    def __append_query_record(self, package):

        assert isinstance(package, DNSResponsePackage)

        package.append_name(self.request.record.name())

        # TYPE
        package.append(chr((self.request.record.record_type >> 8) & 0xFF))
        package.append(chr((self.request.record.record_type >> 0) & 0xFF))

        # CLASS
        package.append(chr((self.request.record.record_class >> 8) & 0xFF))
        package.append(chr((self.request.record.record_class >> 0) & 0xFF))

    def __append_answers(self, package):

        assert isinstance(package, DNSResponsePackage)

        for answer in self.__answers:

            package.append_name(answer['record_name'])

            package.append(chr((answer['record_type'] >> 8) & 0xFF))
            package.append(chr((answer['record_type'] >> 0) & 0xFF))

            package.append(chr((answer['record_class'] >> 8) & 0xFF))
            package.append(chr((answer['record_class'] >> 0) & 0xFF))

            package.append(chr((answer['record_ttl'] >> 24) & 0xFF))
            package.append(chr((answer['record_ttl'] >> 16) & 0xFF))
            package.append(chr((answer['record_ttl'] >> 8) & 0xFF))
            package.append(chr((answer['record_ttl'] >> 0) & 0xFF))

            package.append(chr((len(answer['record_data']) >> 8) & 0xFF))
            package.append(chr((len(answer['record_data']) >> 0) & 0xFF))

            for byte in answer['record_data']:
                package.append(byte)

    def __answer(self, data, record_name=None, record_type=None, record_class=None, record_ttl=None):

        # generic, non rfc1035, answer

        if record_name is None:
            record_name = self.request.record.name()
        if record_type is None:
            record_type = self.request.record.record_type
        if record_class is None:
            record_class = self.request.record.record_class
        if record_ttl is None:
            record_ttl = 60

        self.__answers.append(
            dict(
                record_name=record_name,
                record_type=record_type,
                record_class=record_class,
                record_ttl=record_ttl,
                record_data=data
            )
        )

    @staticmethod
    def __parse_ipv6(text):
        virtual_address = [0, 0, 0, 0, 0, 0, 0, 0]
        for index, part in enumerate(text.split(':')):
            if len(part) == 0:
                break  # stretched
            virtual_address[index] = int(part, 16)
        for index, part in enumerate(reversed(text.split(':'))):
            if len(part) == 0:
                break  # stretched
            virtual_address[7 - index] = int(part, 16)
        return virtual_address

    def answer_a(self, address, record_name=None, record_class=None, record_ttl=None):
        return self.__answer(
            str.join('', map(lambda x: chr(int(x)), address.split('.'))),
            record_type=self.request.record.type_id('A'),
            record_name=record_name, record_class=record_class, record_ttl=record_ttl
        )

    def answer_aaaa(self, address, record_name=None, record_class=None, record_ttl=None):
        parsed_address = self.__parse_ipv6(address)
        return self.__answer(
            str.join('', map(lambda x: chr((x >> 8) & 0xFF) + chr((x >> 0) & 0xFF), parsed_address)),
            record_type=self.request.record.type_id('AAAA'),
            record_name=record_name, record_class=record_class, record_ttl=record_ttl
        )

    def answer_ns(self, name, record_name=None, record_class=None, record_ttl=None):
        return self.__answer(
            DNSResponsePackage.encode_name(name),
            record_type=self.request.record.type_id('NS'),
            record_name=record_name, record_class=record_class, record_ttl=record_ttl
        )

    def answer_ptr(self, name, record_name=None, record_class=None, record_ttl=None):
        return self.__answer(
            DNSResponsePackage.encode_name(name),
            record_type=self.request.record.type_id('PTR'),
            record_name=record_name, record_class=record_class, record_ttl=record_ttl
        )

    def answer_cname(self, name, record_name=None, record_class=None, record_ttl=None):
        return self.__answer(
            DNSResponsePackage.encode_name(name),
            record_type=self.request.record.type_id('CNAME'),
            record_name=record_name, record_class=record_class, record_ttl=record_ttl
        )

    def answer_txt(self, text, record_name=None, record_class=None, record_ttl=None):
        assert len(text) < 256
        return self.__answer(
            chr(len(text)) + text,
            record_type=self.request.record.type_id('TXT'),
            record_name=record_name, record_class=record_class, record_ttl=record_ttl
        )

    def answer_mx(self, name, priority=10, record_name=None, record_class=None, record_ttl=None):
        assert priority < 2 ** 16

        return self.__answer(
            chr((priority >> 8) & 0xFF) + chr((priority >> 0) & 0xFF) +
            DNSResponsePackage.encode_name(name),
            record_type=self.request.record.type_id('MX'),
            record_name=record_name, record_class=record_class, record_ttl=record_ttl
        )

    def answer_soa(self, mname, rname, serial, refresh=900, retry=900, expire=1800, minimum=60,
                   record_name=None, record_class=None, record_ttl=None):

        assert serial < 2 ** 32
        assert refresh < 2 ** 32
        assert retry < 2 ** 32
        assert expire < 2 ** 32

        return self.__answer(

            # MNAME
            DNSResponsePackage.encode_name(mname) +

            # RNAME
            DNSResponsePackage.encode_name(rname) +

            # SERIAL (unsigned 32 bit version number)
            chr((serial >> 24) & 0xFF) + chr((serial >> 16) & 0xFF) +
            chr((serial >> 8) & 0xFF) + chr((serial >> 00) & 0xFF) +

            # REFRESH (32 bit time interval)
            chr((refresh >> 24) & 0xFF) + chr((refresh >> 16) & 0xFF) +
            chr((refresh >> 8) & 0xFF) + chr((refresh >> 00) & 0xFF) +

            # RETRY (32 bit time interval)
            chr((retry >> 24) & 0xFF) + chr((retry >> 16) & 0xFF) +
            chr((retry >> 8) & 0xFF) + chr((retry >> 00) & 0xFF) +

            # EXPIRE (32 bit time value)
            chr((expire >> 24) & 0xFF) + chr((expire >> 16) & 0xFF) +
            chr((expire >> 8) & 0xFF) + chr((expire >> 00) & 0xFF) +

            # MINIMUM (unsigned 32 bit minimum TTL)
            chr((minimum >> 24) & 0xFF) + chr((minimum >> 16) & 0xFF) +
            chr((minimum >> 8) & 0xFF) + chr((minimum >> 00) & 0xFF),

            record_type=self.request.record.type_id('SOA'),
            record_name=record_name, record_class=record_class, record_ttl=record_ttl
        )

    def throw(self, code_description):
        self.__rcode = self.rcode_id(code_description) or int(code_description)

    def generate(self):

        package = DNSResponsePackage()

        self.__append_header(package)
        self.__append_query_record(package)
        self.__append_answers(package)

        #pprint_data(package)

        return package

    def __init__(self, request):

        assert isinstance(request, DNSRequest)
        self.request = request
        self.__answers = list()
        self.__rcode = False


class DNSResolver(Thread):

    def __init__(self, connection, data, lookup):
        super(DNSResolver, self).__init__()
        assert isinstance(connection, GenericConnection)
        self.connection = connection
        self.data = data
        self.lookup = lookup

    def run(self):
        try:
            dns_request = DNSRequest(self.data, self.connection, self.lookup)
            self.connection.send(dns_request.response())
            self.connection.close()
        except OSError:
            return  # closed by client


class GenericSocket(object):

    socket = None
    open = False

    def receive(self):
        raise NotImplementedError()

    def close(self):
        raise NotImplementedError()

    @property
    def type(self):
        return self.__class__.__name__[:5]


class GenericConnection(object):

    remote_address = None
    remote_port = None
    socket_handler = None

    def send(self, data):
        raise NotImplementedError()

    def close(self):
        raise NotImplementedError()


class GenericUPDSocket(GenericSocket):

    def receive(self):
        while self.open:
            try:
                data, address = self.socket.recvfrom(1024)
            except socket.timeout:
                pass
            else:
                return data, UPDConnection(self, address[0], address[1])

    def close(self):
        self.open = False
        return self.socket.close()


class UPDv4Socket(GenericUPDSocket):

    def __init__(self, address='0.0.0.0', port=53):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(1)
        self.socket.bind((address, port))
        self.open = True


class UDPv6Socket(GenericUPDSocket):

    def __init__(self, address='::0', port=53):
        self.socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.socket.settimeout(1)
        self.socket.bind((address, port))
        self.open = True


class UPDConnection(GenericConnection):

    def __init__(self, socket_handler, remote_address, remote_port):
        self.socket_handler = socket_handler
        self.remote_address = remote_address
        self.remote_port = remote_port

    def send(self, data):
        if self.socket_handler.open:
            return self.socket_handler.socket.sendto(data, (self.remote_address, self.remote_port))

    def close(self):
        pass


class GenericTCPSocket(GenericSocket):

    def receive(self):
        while self.open:
            try:
                connection, address = self.socket.accept()
                data = connection.recv(1024)
            except socket.timeout:
                pass
            else:
                # data[0:1] is request length on TCP
                return data[2:], TCPConnection(self, connection, address[0], address[1])

    def close(self):
        self.open = False
        return self.socket.close()


class TCPv4Socket(GenericTCPSocket):

    def __init__(self, address='0.0.0.0', port=53):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(1)
        self.socket.bind((address, port))
        self.socket.listen(1)
        self.open = True


class TCPv6Socket(GenericTCPSocket):

    def __init__(self, address='::0', port=53):
        self.socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.socket.settimeout(1)
        self.socket.bind((address, port))
        self.socket.listen(1)
        self.open = True


class TCPConnection(GenericConnection):

    def __init__(self, socket_handler, remote_connection, remote_address, remote_port):
        self.socket_handler = socket_handler
        self.remote_connection = remote_connection
        self.remote_address = remote_address
        self.remote_port = remote_port

    def send(self, data):
        if self.socket_handler.open:
            # send length information + data
            length = len(data)
            self.remote_connection.send(chr((length >> 8) & 0xFF) + chr((length >> 0) & 0xFF))
            self.remote_connection.send(data)

    def close(self):
        if self.socket_handler.open:
            return self.remote_connection.close()


class DNSServer(Thread):

    def __init__(self, socket_facade):
        super(DNSServer, self).__init__()
        assert isinstance(socket_facade, GenericSocket)
        self.socket_facade = socket_facade
        self.__started = False

    def run(self):

        try:

            while self.__started:
                try:
                    request_data = self.socket_facade.receive()
                    if request_data:
                        data, connection = request_data
                        resolver = DNSResolver(connection, data, self.lookup)
                        resolver.start()
                except Exception, e:
                    logging.debug(e)
                    continue

        except KeyboardInterrupt:
            pass
        finally:
            self.socket_facade.close()

    def start(self):
        self.__started = True
        super(DNSServer, self).start()
        return self

    def stop(self):
        self.__started = False
        self.socket_facade.close()
        return self

    def lookup(self, request, response):
        raise NotImplementedError("DNSServer.answer is not implemented")


class SampleDNSServer(DNSServer):

    def lookup(self, request, response):

        assert isinstance(request, DNSRequest)
        assert isinstance(response, DNSResponse)

        # # Examples:
        # response.answer_a("127.0.0.1", record_ttl=0)
        # response.answer_mx("mx.localhost", priority=20)
        # response.answer_ns("ns.localhost")
        # response.answer_ptr("ptr.localhost")
        # response.answer_aaaa("::1", record_ttl=3)
        # response.answer_cname("another.localhost", record_ttl=4)
        # response.answer_cname("another.record_name", record_name="any.record.name")
        # response.answer_soa("ns1.localhost", "dns-admin.localhost", 1)

        # Simplified DNS resolution Example
        try:

            if request.record.type_name() == 'A':
                result = socket.gethostbyname(request.record.name())
                response.answer_a(result)
                answered = "%s %s" % (request.record.type_name(), str(result))

            else:
                answered = None

        except socket.gaierror:
            response.throw('NXDomain')
            answered = 'NXDomain'

        print("Request from %s:%s:%s for %s (%s %s): %s" % (
            request.connection.socket_handler.type,
            request.connection.remote_address,
            request.connection.remote_port,
            request.record.name(),
            request.record.class_name(),
            request.record.type_name(),
            answered))


def main():
    SampleDNSServer(UPDv4Socket()).start()
    SampleDNSServer(TCPv4Socket()).start()
    SampleDNSServer(TCPv6Socket()).start()
    SampleDNSServer(UDPv6Socket()).start()


if __name__ == '__main__':
    main()
