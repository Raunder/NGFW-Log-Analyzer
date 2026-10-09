import json
import sqlite3
from collections import Counter
from typing import List, Dict

''' Класс логов '''
class LogEntry:
    def __init__(self, data: Dict):
        self.timestamp = data['timestamp']
        self.src_ip = data['src_ip']
        self.dst_ip = data['dst_ip']
        self.port = data['port']
        self.protocol = data['protocol']
        self.action = data['action']

''' Класс Firewall  '''
class FirewallAnalyzer:
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.logs: List[LogEntry] = []

    #Чтение логов из файла json и инициализация объекта LogEntry
    def load_logs(self):
        with open(self.log_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            self.logs = [LogEntry(entry) for entry in data]

    # Фильтрация ip адресов по пороговому значению(по умолчанию - 2) и поиск оборванных соединений
    def find_suspicious_ips(self, threshold: int = 2) -> List[str]:
        drop_counts = Counter(log.src_ip for log in self.logs if log.action == "DROP")
        return [ip for ip, count in drop_counts.items() if count >= threshold]

''' Класс базы данных '''
class DatabaseManager:
    def __init__(self, db_name: str = "anomalies.db"):
        self.db_name = db_name
        self._init_db()

    # Создаем необходимые таблицы
    def _init_db(self):
        with sqlite3.connect(self.db_name) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS suspicious_ips 
                            (ip TEXT PRIMARY KEY, drop_count INTEGER)''')

    # Фиксируем аномалии из логов в БД
    def save_anomalies(self, ips: List[str], logs: List[LogEntry]):
        from collections import Counter
        drop_counts = Counter(log.src_ip for log in logs if log.action == "DROP" and log.src_ip in ips)

        with sqlite3.connect(self.db_name) as conn:
            for ip, count in drop_counts.items():
                conn.execute("INSERT OR REPLACE INTO suspicious_ips (ip, drop_count) VALUES (?, ?)", (ip, count))
        print(f"Сохранено {len(ips)} подозрительных IP в БД.")


if __name__ == "__main__":
    analyzer = FirewallAnalyzer("mock_logs.json")
    analyzer.load_logs()
    suspicious = analyzer.find_suspicious_ips(threshold=2)

    db = DatabaseManager()
    db.save_anomalies(suspicious, analyzer.logs)