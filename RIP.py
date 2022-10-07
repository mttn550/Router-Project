class RIPv2:

    @staticmethod
    def header(code=b'\x01'):
        return code + b'\x02\x00\x00'

    @staticmethod
    def entry(ip, mask, next_hop, metric):
        return b'\x00\x02\x00\x00' + ip + mask + next_hop + b'\x00\x00\x00' + metric.to_bytes(1, 'big')
