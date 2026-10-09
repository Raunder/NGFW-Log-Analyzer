FROM python:3.14

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Запускаем тесты, а затем основной скрипт
CMD ["sh", "-c", "pytest smoke-test.py -v && python main.py"]