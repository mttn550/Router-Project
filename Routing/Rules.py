class L4Rule:

    def __init__(self, type, sock, *data):
        self.data = (type, *data)
        self.sock = sock
        self._time = 30
        self._is_tick = False

    def refresh(self):
        self._time = 30

    def set_tick(self):
        self._is_tick = True

    def tick(self):
        if self._is_tick:
            self._time -= 1
        return self._time == 0

    def __getitem__(self, item):
        return self.data[item]


class Rules:

    def __init__(self):
        self.rules = set()

    def add4(self, type, *data):
        self.rules.add(L4Rule(type, *data))

    def add(self, type, *data):
        self.rules.add((type, *data))

    def get_rule(self, pkt_type, data):
        for rule in self.rules:
            if type(rule) == L4Rule:
                if pkt_type in rule.data and data in rule.data:
                    return rule
            else:
                if pkt_type in rule and not any(i not in rule for i in data):
                    return rule
        return None

    def translate(self, type, index, *data):
        rule = self.get_rule(type, *data)
        if rule is None: return None
        return tuple(rule[i] for i in index)

    def tick(self):
        for rule in self.rules:
            if type(rule) == L4Rule and rule.tick():
                rule.sock.close()
                self.rules.remove(rule)
