# XILLEN Advanced Cryptography Tool

## Описание
Мощный Java инструмент для продвинутой криптографии и анализа безопасности. Инструмент предоставляет комплексные возможности для шифрования, дешифрования, хеширования, генерации ключей и анализа криптографических алгоритмов.

## Возможности
- **Symmetric Encryption**: AES, DES, 3DES, Blowfish, RC4, ChaCha20
- **Asymmetric Encryption**: RSA, DSA, EC, DH
- **Hash Functions**: MD5, SHA-1, SHA-256, SHA-512, SHA3-256, SHA3-512
- **Encryption Modes**: ECB, CBC, CFB, OFB, CTR, GCM
- **Key Generation**: Автоматическая генерация ключей различных размеров
- **Performance Benchmarking**: Тестирование производительности алгоритмов
- **File Analysis**: Анализ энтропии и сжимаемости файлов
- **Hash Cracking**: Взлом хешей с использованием словарей
- **Multi-threading**: Многопоточная обработка для высокой производительности

## Установка

### Требования
- Java 11+ (JDK)
- Maven или Gradle (опционально)

### Сборка
```bash
git clone https://github.com/BengaminButton/xillen-cryptography-advanced
cd xillen-cryptography-advanced

# Компиляция
javac CryptoAdvanced.java

# Создание JAR файла
jar cfm CryptoAdvanced.jar MANIFEST.MF *.class
```

### Запуск
```bash
java CryptoAdvanced [command] [options]
```

## Использование

### Команды

#### 1. Шифрование
```bash
# Шифрование файла
java CryptoAdvanced encrypt AES CBC mykey123 input.txt output.enc

# Шифрование с указанием выходного файла
java CryptoAdvanced encrypt AES CBC mykey123 input.txt encrypted_file.enc
```

#### 2. Дешифрование
```bash
# Дешифрование файла
java CryptoAdvanced decrypt AES CBC mykey123 encrypted_file.enc decrypted_file.txt

# Дешифрование с автоматическим именем
java CryptoAdvanced decrypt AES CBC mykey123 encrypted_file.enc
```

#### 3. Хеширование
```bash
# Вычисление MD5 хеша
java CryptoAdvanced hash MD5 input.txt

# Вычисление SHA-256 хеша
java CryptoAdvanced hash SHA-256 input.txt

# Вычисление SHA-512 хеша
java CryptoAdvanced hash SHA-512 input.txt
```

#### 4. Генерация ключей
```bash
# Генерация RSA ключа 2048 бит
java CryptoAdvanced generate RSA 2048

# Генерация AES ключа 256 бит
java CryptoAdvanced generate AES 256

# Генерация DSA ключа 1024 бит
java CryptoAdvanced generate DSA 1024
```

#### 5. Бенчмарки
```bash
# Запуск тестов производительности
java CryptoAdvanced benchmark
```

#### 6. Анализ файлов
```bash
# Анализ энтропии файла
java CryptoAdvanced analyze input.txt

# Анализ бинарного файла
java CryptoAdvanced analyze binary.exe
```

#### 7. Взлом хешей
```bash
# Попытка взлома хеша
java CryptoAdvanced crack 5f4dcc3b5aa765d61d8327deb882cf99 wordlist.txt
```

### Параметры командной строки

#### Шифрование/Дешифрование
- `algorithm`: Алгоритм шифрования (AES, DES, Blowfish, etc.)
- `mode`: Режим работы (ECB, CBC, CFB, OFB, CTR, GCM)
- `key`: Ключ шифрования
- `input`: Входной файл
- `output`: Выходной файл (опционально)

#### Хеширование
- `algorithm`: Алгоритм хеширования (MD5, SHA-1, SHA-256, etc.)
- `input`: Входной файл

#### Генерация ключей
- `algorithm`: Алгоритм (RSA, DSA, AES, DES, Blowfish)
- `keySize`: Размер ключа в битах (опционально)

#### Анализ файлов
- `input`: Файл для анализа

#### Взлом хешей
- `hash`: Хеш для взлома
- `wordlist`: Файл со словарем паролей

## Поддерживаемые алгоритмы

### Симметричное шифрование
- **AES**: Advanced Encryption Standard (128, 192, 256 бит)
- **DES**: Data Encryption Standard (56 бит)
- **3DES**: Triple DES (168 бит)
- **Blowfish**: Блочный шифр (32-448 бит)
- **RC4**: Потоковый шифр
- **ChaCha20**: Современный потоковый шифр

### Асимметричное шифрование
- **RSA**: Rivest-Shamir-Adleman (512-4096 бит)
- **DSA**: Digital Signature Algorithm (512-3072 бит)
- **EC**: Elliptic Curve Cryptography
- **DH**: Diffie-Hellman Key Exchange

### Хеш-функции
- **MD5**: Message Digest Algorithm 5 (128 бит)
- **SHA-1**: Secure Hash Algorithm 1 (160 бит)
- **SHA-256**: Secure Hash Algorithm 256 (256 бит)
- **SHA-512**: Secure Hash Algorithm 512 (512 бит)
- **SHA3-256**: SHA-3 256 (256 бит)
- **SHA3-512**: SHA-3 512 (512 бит)

### Режимы шифрования
- **ECB**: Electronic Codebook
- **CBC**: Cipher Block Chaining
- **CFB**: Cipher Feedback
- **OFB**: Output Feedback
- **CTR**: Counter
- **GCM**: Galois/Counter Mode

## Примеры использования

### Шифрование конфиденциального файла
```bash
# Шифрование с AES-256 в режиме CBC
java CryptoAdvanced encrypt AES CBC "my_secure_key_256" config.txt config.enc

# Результат: config.enc - зашифрованный файл
```

### Создание хеша для проверки целостности
```bash
# Создание SHA-256 хеша
java CryptoAdvanced hash SHA-256 important_file.pdf

# Результат: SHA-256 hash: a1b2c3d4e5f6...
```

### Генерация ключей для приложения
```bash
# Генерация RSA ключа 2048 бит
java CryptoAdvanced generate RSA 2048

# Результат: публичный и приватный ключи
```

### Тестирование производительности
```bash
# Запуск бенчмарков
java CryptoAdvanced benchmark

# Результат: таблица производительности алгоритмов
```

### Анализ подозрительного файла
```bash
# Анализ энтропии
java CryptoAdvanced analyze suspicious.exe

# Результат: размер, энтропия, сжимаемость, частоты байтов
```

## Выходные данные

### Результаты шифрования/дешифрования
- Статус операции
- Имя выходного файла
- Размер обработанных данных

### Результаты хеширования
- Алгоритм хеширования
- Хеш в шестнадцатеричном формате
- Сохранение в результатах

### Результаты генерации ключей
- Публичный ключ (для асимметричных алгоритмов)
- Приватный ключ (для асимметричных алгоритмов)
- Симметричный ключ (для симметричных алгоритмов)

### Результаты бенчмарков
- Время выполнения для каждого алгоритма
- Сортировка по производительности
- Статистика по типам операций

### Результаты анализа файлов
- Размер файла
- Энтропия (мера случайности)
- Коэффициент сжатия
- Частоты байтов

## Безопасность

### Рекомендации
- Используйте сильные ключи (минимум 256 бит для AES)
- Избегайте режима ECB для шифрования
- Регулярно обновляйте ключи
- Используйте криптографически стойкие генераторы случайных чисел
- Проверяйте целостность файлов с помощью хешей

### Ограничения
- MD5 и SHA-1 считаются криптографически слабыми
- DES устарел и не рекомендуется для новых приложений
- Размер ключа влияет на безопасность и производительность

## Производительность

### Оптимизации
- Многопоточная обработка
- Буферизованные операции ввода/вывода
- Эффективные реализации алгоритмов
- Оптимизированные режимы шифрования

### Метрики
- Время шифрования/дешифрования
- Скорость хеширования
- Использование памяти
- Загрузка CPU

## Требования

### Системные требования
- Java 11 или выше
- Минимум 2GB RAM
- Достаточно места на диске для файлов
- Поддержка криптографических провайдеров

### Зависимости
- Стандартные библиотеки Java Cryptography Architecture (JCA)
- Встроенные криптографические провайдеры
- Многопоточные библиотеки Java

## Авторы
- **@Bengamin_Button** - Основной разработчик
- **@XillenAdapter** - Технический консультант

## Ссылки
- 🌐 **Website**: https://benjaminbutton.ru/
- 🔗 **Organization**: https://xillenkillers.ru/
- 📱 **Telegram**: t.me/XillenAdapter

## Лицензия
MIT License - свободное использование и модификация

## Поддержка
Для вопросов и предложений обращайтесь через Telegram или создавайте Issues на GitHub.

---
*XILLEN Advanced Cryptography Tool - профессиональный инструмент для криптографии и анализа безопасности*
