class IGMPv3:

    @staticmethod
    def report(mode=''):
        if mode == 'lev':
            leave = b'\x03'  # Change to INCLUDE
        elif mode == 'join':
            leave = b'\x04'  # Change to EXCLUDE
        else:
            leave = b'\x02'  # EXCLUDE
        data = b'\x22\x00\x00\x00\x00\x00\x00\x01' + \
               leave + b'\x00\x00\x00\xe0\x00\x00\x09'  # Group Record: 224.0.0.9 (Router Multicast)
        checksum = IGMPv3.calc_checksum(data)
        data = data[:2] + checksum.to_bytes(2, 'big') + data[4:]
        return data

    @staticmethod
    def join():
        return IGMPv3.report(mode='join')

    @staticmethod
    def leave():
        return IGMPv3.report(mode='lev')

    @staticmethod
    def ones_complement_sum(n1, n2):
        result = n1 + n2
        mod = 1 << 16  # First negative signed number
        return result if result < mod else (result+1) % mod

    @staticmethod
    def calc_checksum(mes):
        sum = 0
        while mes:
            num = int.from_bytes(mes[:2], 'big')
            sum = IGMPv3.ones_complement_sum(sum, num)
            mes = mes[2:]
        return sum ^ 0xffff
