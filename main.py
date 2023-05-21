import random
import hashlib
import sys
import os
import time
from vt import Client, APIError
import requests

API_KEY = ''  # Укажите ваш API-ключ VirusTotal
API_TOKEN = '' # Укажите токен Telegram бота
user_id = 111111 # Укажите user id Telegram
BUFFER_SIZE = 256


def calculate_sha256(file_path):
  sha256_hash = hashlib.sha256()

  with open(file_path, 'rb') as f:
    for chunk in iter(lambda: f.read(BUFFER_SIZE), b''):
      sha256_hash.update(chunk)

  return sha256_hash.hexdigest()


def pump_file(file_path, pump_size):
  bytes_file_size = pump_size * pow(1024, 2)

  with open(file_path, 'rb') as f:
      data = f.read()

  timestamp = str(int(time.time()))
  file_name = f'new_file_{timestamp}.exe'

  with open(file_name, 'wb') as f:
    f.write(data)
    remaining_bytes = bytes_file_size - len(data)

    while remaining_bytes > 0:
      random_chunk_size = min(BUFFER_SIZE, remaining_bytes)
      random_chunk = bytes(random.randint(0, 255) for _ in range(random_chunk_size))
      f.write(random_chunk)
      remaining_bytes -= random_chunk_size

  return file_name


def upload_file(file_path):
  client = Client(API_KEY)
  try:
    _extracted_from_upload_file_4(file_path, client)
  except APIError as e:
    print('Произошла ошибка при загрузке файла на VirusTotal.')
    print('Ошибка API:', e)
    return None

  client.close()


def _extracted_from_upload_file_4(file_path, client):
  with open(file_path, 'rb') as f:
    client.scan_file(f, wait_for_completion=True)

  file = client.get_object(f"/files/{new_hash}")
  stats = file.last_analysis_stats

  positives = stats.get('malicious')
  unsupported = stats.get('type-unsupported')
  undetected = stats.get('undetected')
  safe = stats.get('harmless')

  api_url = f'https://api.telegram.org/bot{API_TOKEN}/sendMessage'

  message = f'Файл успешно загружен на VirusTotal\nОбнаружено: {positives}\nНе поддерживается: {unsupported}\nНе определен: {undetected}\nБезопасно: {safe}'

  # print(message)
  params = {'chat_id': chat_id, 'text': message}
  try:
    requests.get(api_url, params=params)
  except Exception:
    pass


def delete_file(file_path):
  os.remove(file_path)
  print(f'Файл {file_path} удален.')


# Запрос пути к файлу
file_path = 'ПУТЬКФАЙЛУ'

if not os.path.isfile(file_path):
  print("Файл не найден!")
  sys.exit()

original_hash = calculate_sha256(file_path)
print(f'Исходный хеш: {original_hash}\n----------------------------------------------')

while True:
  print('Памплю файл...')
  pump_size = random.randint(1, 8)

  pumped_file = pump_file(file_path, pump_size)

  new_hash = calculate_sha256(pumped_file)
  print(f'Новый хеш: {new_hash}')

  print('Загружаю файл на VirusTotal...')
  upload_file(pumped_file)

  print('----------------------------------------------')

  delete_file(pumped_file)
