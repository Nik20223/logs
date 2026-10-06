#!/usr/bin/env python3
"""Анализ логов веб-сервера (access.log).

Скрипт принимает путь к файлу лога или к директории с логами, собирает
статистику за один проход по каждому файлу, сохраняет её в json-файл и
выводит в терминал.
"""

import argparse
import heapq
import json
import os
import re
import sys
from collections import Counter

# Формат записи в логе:
# %h - - %t "%r" %s %b "%{Referer}" "%{User-Agent}" %d
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) '
    r'(?P<size>\S+) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)" '
    r'(?P<duration>\d+)\s*$'
)

# HTTP-методы, статистика по которым обязательна в отчёте.
HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD")

# Сколько записей показывать в топах.
TOP_IPS_LIMIT = 3
TOP_SLOW_LIMIT = 3


def parse_args(argv=None):
    """Разобрать аргументы командной строки."""
    parser = argparse.ArgumentParser(
        description="Скрипт анализа логов веб-сервера (access.log).",
    )
    parser.add_argument(
        "path",
        help="Путь к файлу лога или к директории с логами",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=".",
        help="Директория для сохранения json-файлов со статистикой "
        "(по умолчанию — текущая)",
    )
    return parser.parse_args(argv)


def collect_log_files(path):
    """Вернуть список лог-файлов для обработки.

    Если передан файл — обрабатывается только он. Если передана
    директория — обрабатываются все файлы внутри неё.
    """
    if os.path.isfile(path):
        return [path]
    if os.path.isdir(path):
        return sorted(
            os.path.join(path, name)
            for name in os.listdir(path)
            if os.path.isfile(os.path.join(path, name))
        )
    raise FileNotFoundError(f"Путь не найден: {path}")


def analyze_file(file_path):
    """Собрать статистику по одному лог-файлу за один проход."""
    total_requests = 0
    methods = Counter()
    ip_counter = Counter()
    # min-heap по длительности: храним не более TOP_SLOW_LIMIT записей.
    slowest = []

    with open(file_path, encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            match = LOG_PATTERN.match(line)
            if match is None:
                continue

            data = match.groupdict()
            total_requests += 1

            request_parts = data["request"].split()
            method = request_parts[0] if request_parts else "-"
            url = request_parts[1] if len(request_parts) > 1 else "-"

            methods[method] += 1
            ip_counter[data["ip"]] += 1

            duration = int(data["duration"])
            entry = (duration, data["ip"], method, url, data["time"])
            if len(slowest) < TOP_SLOW_LIMIT:
                heapq.heappush(slowest, entry)
            elif duration > slowest[0][0]:
                heapq.heapreplace(slowest, entry)

    slowest.sort(key=lambda entry: entry[0], reverse=True)

    return {
        "file": os.path.abspath(file_path),
        "total_requests": total_requests,
        "methods": {method: methods[method] for method in HTTP_METHODS},
        "top_ips": [
            {"ip": ip, "requests": count}
            for ip, count in ip_counter.most_common(TOP_IPS_LIMIT)
        ],
        "top_slowest_requests": [
            {
                "method": method,
                "url": url,
                "ip": ip,
                "duration_ms": duration,
                "time": time,
            }
            for duration, ip, method, url, time in slowest
        ],
    }


def save_stats(stats, output_dir):
    """Сохранить статистику в json-файл и вернуть путь к нему."""
    os.makedirs(output_dir, exist_ok=True)
    json_name = f"{os.path.basename(stats['file'])}.json"
    json_path = os.path.join(output_dir, json_name)
    with open(json_path, "w", encoding="utf-8") as json_file:
        json.dump(stats, json_file, ensure_ascii=False, indent=4, sort_keys=False)
    return json_path


def print_stats(stats, json_path):
    """Вывести статистику в терминал."""
    print("=" * 60)
    print(f"Файл: {stats['file']}")
    print(f"Всего запросов: {stats['total_requests']}")

    print("Запросы по HTTP-методам:")
    for method, count in stats["methods"].items():
        print(f"    {method}: {count}")

    print("Топ-3 IP-адресов по количеству запросов:")
    for index, item in enumerate(stats["top_ips"], start=1):
        print(f"    {index}. {item['ip']} — {item['requests']} запросов")

    print("Топ-3 самых долгих запросов:")
    for index, item in enumerate(stats["top_slowest_requests"], start=1):
        print(
            f"    {index}. {item['method']} {item['url']} "
            f"IP: {item['ip']} {item['duration_ms']} мс [{item['time']}]"
        )

    print(f"Результат сохранён в: {json_path}")
    print("=" * 60)


def main(argv=None):
    args = parse_args(argv)

    try:
        log_files = collect_log_files(args.path)
    except FileNotFoundError as error:
        print(error, file=sys.stderr)
        return 1

    if not log_files:
        print(f"В '{args.path}' не найдено файлов для анализа", file=sys.stderr)
        return 1

    for file_path in log_files:
        stats = analyze_file(file_path)
        json_path = save_stats(stats, args.output)
        print_stats(stats, json_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
