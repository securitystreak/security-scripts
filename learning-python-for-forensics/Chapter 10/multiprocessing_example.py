import multiprocessing
import time

def f(x):
    t = 0
    while t < 10:
        print "Running ", x, "-", t
        t += 1
        time.sleep(x)

if __name__ == '__main__':
    p1 = multiprocessing.Process(target=f, args=(1,))
    p2 = multiprocessing.Process(target=f, args=(2,))

    p1.start()
    time.sleep(0.5)
    p2.start()

    while True:
        if not p2.is_alive():
            p1.terminate()
            break
    print "Both processes finished"
