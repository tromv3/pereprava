"""Запускает все тесты exitctl: python3 tests/run_all.py

Тесты не трогают серверы и сеть: Xray заменён заглушками, а скан SNI идёт по
локальным TLS-серверам на 127.0.0.x. Для тестов SNI нужен openssl в PATH.
"""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = ["test_exitctl.py", "test_sni_check.py", "test_sni_scan.py"]


def main():
    failed = []
    for name in TESTS:
        t0 = time.time()
        r = subprocess.run([sys.executable, "-X", "utf8", "-B", os.path.join(HERE, name)],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        ok = r.returncode == 0
        print(f'{"OK    " if ok else "ОШИБКА"} {name} ({time.time() - t0:.0f} с)')
        if not ok:
            failed.append(name)
            print(r.stdout[-4000:])
            print(r.stderr[-4000:])
    print("Все тесты прошли." if not failed else "Упали: " + ", ".join(failed))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
