import threading, time
FILE_NAME = 'helloworld.txt'


def func(id):
    global n
    s1 = time.time_ns()
    file = open(FILE_NAME)
    file.read()
    file.close()
    n[id] += time.time_ns() - s1


n = [0, 0]
nt = 0
N = 15000


for i in range(N):
    t1 = threading.Thread(target=func, args=(0,))
    t2 = threading.Thread(target=func, args=(1,))
    start = time.time_ns()
    t1.start(); t2.start()
    t1.join(); t2.join()
    nt += time.time_ns() - start

print(f'time1: {n[0] / N} ns')
print(f'time2: {n[1] / N} ns')
print(f'time: {nt / N} ns')
print(f'{int(200 * (nt - sum(n)) / (nt + sum(n)))}% difference')