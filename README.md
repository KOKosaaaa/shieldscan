# ShieldScan — Кроссплатформенный аудитор безопасности v2.0

## Что это?

ShieldScan — инструмент для проверки безопасности ПК. Автоматически определяет ОС (Windows/Linux) и запускает 36 проверок на Windows / 32 на Linux.

### Что проверяет:
- Антивирус, брандмауэр, UAC, Secure Boot, BitLocker
- Открытые порты, подозрительные соединения, DNS, ARP-спуфинг
- Автозагрузка (безопасность + анализ ненужных программ)
- Обновления, политика паролей, RDP, SMBv1, PowerShell policy
- **Поиск вредоносного ПО**: аномалии процессов, скан путей малвари, цифровые подписи .exe, проверка хешей через VirusTotal
- И многое другое

---

## Содержимое архива

```
ShieldScan/
├── security_auditor.py              ← Основной скрипт (Python)
├── build.bat                        ← Сборка в .exe (Windows)
├── badusb/
│   ├── badusb_shieldscan_online.txt ← DuckyScript: скачивает .exe из интернета (рекомендуемый)
│   ├── badusb_shieldscan_usb.txt    ← DuckyScript: запускает .exe с USB-флешки (с админом)
│   ├── badusb_shieldscan_lite.txt   ← DuckyScript: запускает .exe с USB-флешки (без админа)
│   └── badusb_shieldscan_python.txt ← DuckyScript: скачивает и запускает через Python
└── README.md                        ← Этот файл
```

---

## Быстрый старт

### Вариант 1: Просто запустить на своём ПК

```bash
# Установить зависимость
pip install rich

# Запустить (Linux — через sudo, Windows — от администратора)
python security_auditor.py

# С экспортом в JSON
python security_auditor.py --export
```

### Вариант 2: Собрать в .exe (Windows)

1. Положи `security_auditor.py` и `build.bat` в одну папку
2. Дважды кликни `build.bat`
3. Жди 1-2 минуты
4. Готовый `ShieldScan.exe` появится в папке `dist/` и в текущей папке
5. Этот .exe можно запускать на любой Windows без Python

### Вариант 3: Flipper Zero BadUSB (рекомендуемый — через интернет)

Всё на одном Flipper, флешка не нужна. Нужен только интернет на целевом ПК.

**Подготовка (один раз):**

1. Собери `ShieldScan.exe` через `build.bat`
2. Залей `.exe` на GitHub:
   - Создай репозиторий (например `shieldscan`)
   - Зайди в Releases → Create new release
   - Прикрепи `ShieldScan.exe` как Asset
   - Опубликуй и скопируй прямую ссылку на файл
   - Ссылка будет вида: `https://github.com/ТВОЙ_НИК/shieldscan/releases/download/v1.0/ShieldScan.exe`
3. Открой `badusb/badusb_shieldscan_online.txt`
4. Найди строку `ВСТАВЬ_СЮДА_ПРЯМУЮ_ССЫЛКУ_НА_EXE` и замени на свою ссылку
5. Скопируй файл на SD-карту Flipper: `SD:\badusb\badusb_shieldscan_online.txt`

**Использование:**

1. Подключи Flipper Zero к целевому ПК
2. На Flipper: Bad USB → badusb_shieldscan_online → Run
3. Flipper автоматически:
   - Откроет PowerShell
   - Запросит права администратора (UAC)
   - Скачает ShieldScan.exe
   - Запустит полный скан
   - Удалит .exe после завершения

### Вариант 4: Flipper Zero BadUSB + USB-флешка

Если на целевом ПК нет интернета.

**Подготовка:**
1. Собери `ShieldScan.exe`
2. Положи `ShieldScan.exe` в корень обычной USB-флешки
3. Скопируй `badusb/badusb_shieldscan_usb.txt` на SD Flipper в `/badusb/`

**Использование:**
1. Вставь USB-флешку с `ShieldScan.exe` в ПК
2. Подожди пару секунд
3. Подключи Flipper → Bad USB → badusb_shieldscan_usb → Run

---

## VirusTotal (опционально)

Для проверки хешей файлов через VirusTotal нужен бесплатный API-ключ.

1. Зарегистрируйся: https://www.virustotal.com/gui/join-us
2. Скопируй API-ключ из профиля
3. Перед запуском:
   ```
   # Windows
   set VT_API_KEY=твой_ключ_сюда
   ShieldScan.exe

   # Linux
   export VT_API_KEY=твой_ключ_сюда
   python security_auditor.py
   ```

Без ключа все остальные проверки работают нормально, просто VirusTotal-проверка покажет "API-ключ не задан".

---

## Оценка безопасности

ShieldScan выдаёт оценку от 0 до 100:

| Оценка | Уровень | Описание |
|--------|---------|----------|
| 80-100 | A | Система хорошо защищена |
| 60-79  | B | Есть моменты для улучшения |
| 40-59  | C | Рекомендуется устранить проблемы |
| 0-39   | D | Серьёзные уязвимости! |

---

## Требования

- **Python**: 3.10+ (только для запуска .py, для .exe не нужен)
- **Библиотеки**: `rich` (устанавливается автоматически через build.bat)
- **ОС**: Windows 10/11 или Linux (Ubuntu, Debian, Fedora, etc.)
- **Рекомендуется**: запуск от администратора/sudo для полноты проверок
- **Flipper Zero**: Momentum или стандартная прошивка (для BadUSB)

---

## Лицензия

MIT — используй как хочешь.
