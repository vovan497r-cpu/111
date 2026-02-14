#!/usr/bin/env python3
import os
import re
import io
import csv
import json
import mmap
import queue
import email
import hashlib
import zipfile
import threading
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

# ---------- Paths ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

FOUND_TXT = os.path.join(RESULTS_DIR, 'found_data.txt')
FOUND_JSON = os.path.join(RESULTS_DIR, 'found_data.json')
FOUND_CSV = os.path.join(RESULTS_DIR, 'found_data.csv')
LOG_PATH = os.path.join(RESULTS_DIR, 'scanner.log')

# ---------- Patterns (precompiled) ----------
RAW_SCAN_PATTERNS = {
    'Email': [
        {'name': 'Email', 'pattern': r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'},
    ],
    'Login': [
        {'name': 'Login', 'pattern': r'(?i)(login|username|user)[\s:=]+([^\s\n]+)'},
    ],
    'Password': [
        {'name': 'Email:Pass', 'pattern': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[\s:;|,][^\s]+'},
        {'name': 'Password', 'pattern': r'(?i)(password|pass|pwd)[\s:=]+([^\s\n]+)'},
    ],
    'URL Login:Pass': [
        {'name': 'URL Credentials', 'pattern': r'https?://[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@[^\s]+'},
    ],
    'Gift Card': [
        {'name': 'STEAM', 'pattern': r'\b[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b'},
        {'name': 'AMAZON', 'pattern': r'\b[A-Z0-9]{4}-[A-Z0-9]{6}-[A-Z0-9]{4}\b'},
        {'name': 'XBOX', 'pattern': r'\b[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b'},
    ],
    'Promo Code': [
        {'name': 'Promo', 'pattern': r'(?i)(promo|promocode|coupon)[\s:=]+([A-Z0-9-]{4,20})'},
    ],
    'Voucher': [
        {'name': 'Voucher', 'pattern': r'(?i)(voucher|code)[\s:=]+([A-Z0-9-]{6,20})'},
    ],
    'Bank Card': [
        {'name': 'Card Number', 'pattern': r'\b(?:\d[ -]*?){13,19}\b'},
        {'name': 'CVV', 'pattern': r'(?i)(cvv|cvc|security code)[\s:=]+(\d{3,4})'},
        {'name': 'Expiry', 'pattern': r'\b(0[1-9]|1[0-2])/(\d{2}|\d{4})\b'},
    ],
    'Bank Account': [
        {'name': 'IBAN', 'pattern': r'\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b'},
        {'name': 'Account Number', 'pattern': r'(?i)(account|acc)[\s:=]+(\d{8,20})'},
    ],
    'Phone': [
        {'name': 'Phone', 'pattern': r'\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}'},
    ],
    'Address': [
        {'name': 'Address', 'pattern': r'\d+\s+[\w\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)'},
    ],
    'Crypto Address': [
        {'name': 'BTC', 'pattern': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,40}\b'},
        {'name': 'BTC (Bech32)', 'pattern': r'\bbc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{25,90}\b'},
        {'name': 'ETH/BSC', 'pattern': r'\b0x[a-fA-F0-9]{40}\b'},
        {'name': 'TRX', 'pattern': r'\bT[a-zA-Z0-9]{33}\b'},
        {'name': 'SOL', 'pattern': r'\b[1-9A-HJ-NP-Za-km-z]{32,44}\b'},
    ],
    'Private Key': [
        {'name': 'BTC (WIF)', 'pattern': r'\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b'},
        {'name': 'ETH/HEX', 'pattern': r'\b(0x)?[a-fA-F0-9]{64}\b'},
    ],
    'Public Key': [
        {'name': 'Public Key', 'pattern': r'\b04[a-fA-F0-9]{128}\b'},
    ],
    'Seed Phrase': [
        {'name': '12/24 words', 'pattern': r'\b(([a-z]{3,8}\s+){11}[a-z]{3,8}|([a-z]{3,8}\s+){23}[a-z]{3,8})\b'},
    ],
    'Token': [
        {'name': 'JWT', 'pattern': r'\b(ey[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+)\b'},
        {'name': 'Discord', 'pattern': r'\b([a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9-_]{27,}|mfa\.[a-zA-Z0-9_-]{84})\b'},
    ],
    'Cookie': [
        {'name': 'Cookie', 'pattern': r'(?i)(cookie|set-cookie)[\s:=]+([^\n;]+)'},
    ],
    'API Key': [
        {'name': 'API Key', 'pattern': r'(?i)(api[_-]?key|apikey)[\s:=]+([a-zA-Z0-9_-]{16,64})'},
    ],
    'User Agent': [
        {'name': 'User-Agent', 'pattern': r'(?i)(user-agent|useragent)[\s:=]+([^\n]+)'},
    ],
    'Balance': [
        {'name': 'Balance', 'pattern': r'(?i)(balance|amount)[\s:=]+(\$?\d+\.?\d*)'},
    ],
}

COMPILED_PATTERNS = {}
for cat, items in RAW_SCAN_PATTERNS.items():
    COMPILED_PATTERNS[cat] = []
    for it in items:
        pat = it['pattern']
        flags = 0
        if pat.startswith('(?i)'):
            flags |= re.IGNORECASE
            pat = pat[4:]
        COMPILED_PATTERNS[cat].append({
            'name': it['name'],
            'regex': re.compile(pat, flags)
        })

EMAIL_REGEX = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')

def _luhn_check(num: str) -> bool:
    num = re.sub(r"\D", "", num)
    if not num:
        return False
    s = 0
    alt = False
    for d in reversed(num):
        n = ord(d) - 48
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        s += n
        alt = not alt
    return s % 10 == 0

def validate_finding(category: str, type_name: str, value: str) -> str:
    try:
        if category == 'Email' or type_name.lower().startswith('email'):
            return 'good' if EMAIL_REGEX.fullmatch(value or '') else 'invalid'
        if category == 'Bank Card' and type_name == 'Card Number':
            return 'good' if _luhn_check(value) else 'invalid'
        # Default: cannot validate strictly
        return 'good'
    except Exception:
        return 'invalid'

# ---------- Logging ----------
def log_to_file(message: str):
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception:
        pass

# ---------- Core scanning helpers ----------
def iter_text_lines_from_path(path: Path, chunk_size: int = 1024 * 1024):
    try:
        # quick binary sniff
        with open(path, 'rb') as fb:
            head = fb.read(8192)
            if b'\x00' in head:
                return
        # stream lines in text mode
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                yield line.rstrip('\n')
    except Exception:
        return


def read_json_text(path: Path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return None


def iter_eml_text(path: Path):
    try:
        with open(path, 'rb') as f:
            msg = email.message_from_binary_file(f)
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == 'text/plain':
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        text = payload.decode(charset, errors='ignore')
                    except Exception:
                        text = payload.decode('utf-8', errors='ignore')
                    for line in text.splitlines():
                        yield line
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                try:
                    text = payload.decode(charset, errors='ignore')
                except Exception:
                    text = payload.decode('utf-8', errors='ignore')
                for line in text.splitlines():
                    yield line
    except Exception:
        return


def iter_zip_members_text(zip_path: Path, max_bytes_per_member: int = 32 * 1024 * 1024):
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                try:
                    with z.open(info, 'r') as f:
                        read = 0
                        decoder = io.TextIOWrapper(io.BufferedReader(f, buffer_size=1024*1024), encoding='utf-8', errors='ignore')
                        for line in decoder:
                            yield info.filename, line.rstrip('\n')
                            read += len(line)
                            if read >= max_bytes_per_member:
                                break
                except Exception:
                    continue
    except Exception:
        return

# ---------- Scanner GUI ----------
class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 Сканер конфиденциальных данных (optimized)")
        self.root.geometry("1600x900")

        self.is_running = False
        self.stop_requested = False
        self.current_results = []
        self.all_findings = []
        self.seen_hashes = set()

        self.metrics = {
            'files_processed': 0,
            'total_files': 0,
            'lines_scanned': 0,
            'findings_total': 0,
            'findings_good': 0,
            'findings_invalid': 0,
        }

        self.category_vars = {}
        self.keyword_var = tk.StringVar()
        self.threads_var = tk.StringVar(value="8")
        self.sequential = tk.BooleanVar(value=False)
        self.limit_var = tk.StringVar(value="")
        self.safe_ui = tk.BooleanVar(value=True)
        self.ui_rows_limit_var = tk.StringVar(value="2000")
        self.loading_files = False

        self.log_queue = queue.Queue(maxsize=1000)
        self.result_queue = queue.Queue(maxsize=5000)
        self.stats_queue = queue.Queue(maxsize=1000)

        self._build_ui()
        self._tick_queues()

    # ---------- UI ----------
    def _build_ui(self):
        main_container = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        left_panel = ttk.Frame(main_container, width=300)
        main_container.add(left_panel, weight=0)
        right_panel = ttk.Frame(main_container)
        main_container.add(right_panel, weight=1)

        ttk.Label(left_panel, text="Параметры парсинга", font=('Arial', 12, 'bold')).pack(pady=5)

        keyword_frame = ttk.LabelFrame(left_panel, text="Ключевые слова")
        keyword_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Entry(keyword_frame, textvariable=self.keyword_var).pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(keyword_frame, text="(через запятую)", font=('Arial', 8)).pack()

        threads_frame = ttk.LabelFrame(left_panel, text="Потоки и ограничения")
        threads_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Spinbox(threads_frame, from_=1, to=64, textvariable=self.threads_var, width=10).pack(padx=5, pady=5)
        ttk.Checkbutton(threads_frame, text="Последовательно", variable=self.sequential).pack(padx=5, pady=2, anchor=tk.W)
        limit_row = ttk.Frame(threads_frame)
        limit_row.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(limit_row, text="Первые N файлов:").pack(side=tk.LEFT)
        ttk.Entry(limit_row, textvariable=self.limit_var, width=10).pack(side=tk.LEFT, padx=5)
        ui_row = ttk.Frame(threads_frame)
        ui_row.pack(fill=tk.X, padx=5, pady=2)
        ttk.Checkbutton(ui_row, text="Без всплывающих окон (Safe UI)", variable=self.safe_ui).pack(side=tk.LEFT)
        ttk.Label(ui_row, text="Лимит строк в таблице:").pack(side=tk.LEFT, padx=8)
        ttk.Entry(ui_row, textvariable=self.ui_rows_limit_var, width=8).pack(side=tk.LEFT)

        categories_frame = ttk.LabelFrame(left_panel, text="Категории для парсинга")
        categories_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        canvas = tk.Canvas(categories_frame)
        scrollbar = ttk.Scrollbar(categories_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        ttk.Button(left_panel, text="Выбрать все", command=self._select_all).pack(fill=tk.X, padx=5, pady=2)
        ttk.Button(left_panel, text="Снять все", command=self._deselect_all).pack(fill=tk.X, padx=5, pady=2)

        for category in COMPILED_PATTERNS.keys():
            var = tk.BooleanVar(value=True)
            self.category_vars[category] = var
            ttk.Checkbutton(scrollable_frame, text=category, variable=var).pack(anchor=tk.W, padx=5, pady=2)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Right panel
        top_frame = ttk.Frame(right_panel)
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        self.btn_file = ttk.Button(top_frame, text="📄 Файл", command=self._load_file, width=15)
        self.btn_file.pack(side=tk.LEFT, padx=2)
        self.btn_folder = ttk.Button(top_frame, text="📁 Папка", command=self._load_folder, width=15)
        self.btn_folder.pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text="🧪 Тестовая папка", command=self._create_test_data, width=18).pack(side=tk.LEFT, padx=2)
        self.start_btn = ttk.Button(top_frame, text="▶ Старт", command=self._start, width=12)
        self.start_btn.pack(side=tk.LEFT, padx=2)
        self.stop_btn = ttk.Button(top_frame, text="⏹ Стоп", command=self._stop, width=12, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text="💾 Сохранить", command=self._save_results, width=15).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text="📂 По аккаунтам", command=self._save_by_accounts, width=15).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text="📥 Скачать логи", command=self._download_logs, width=15).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text="🗑 Очистить", command=self._clear, width=12).pack(side=tk.LEFT, padx=2)

        # Manual path loader
        path_row = ttk.Frame(right_panel)
        path_row.pack(fill=tk.X, padx=5, pady=4)
        ttk.Label(path_row, text="Путь к папке:").pack(side=tk.LEFT)
        self.path_var = tk.StringVar()
        self.path_entry = ttk.Entry(path_row, textvariable=self.path_var, width=60)
        self.path_entry.pack(side=tk.LEFT, padx=6)
        ttk.Button(path_row, text="Загрузить путь", command=self._load_folder_from_path, width=16).pack(side=tk.LEFT)

        stats_frame = ttk.LabelFrame(right_panel, text="Статистика в реальном времени")
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        self.stats_text = tk.Text(stats_frame, height=4, state='disabled', font=('Courier', 9))
        self.stats_text.pack(fill=tk.X, padx=5, pady=5)

        self.status_var = tk.StringVar(value="Готов к работе")
        ttk.Label(right_panel, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W).pack(fill=tk.X, padx=5, pady=2)

        progress_frame = ttk.Frame(right_panel)
        progress_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(progress_frame, text="Прогресс:").pack(side=tk.LEFT, padx=5)
        self.progress_bar = ttk.Progressbar(progress_frame, length=400, mode='determinate')
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        results_frame = ttk.LabelFrame(right_panel, text="Найденные данные")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        columns = ('Категория', 'Тип', 'Статус', 'Значение', 'Аккаунт', 'Файл', 'Строка')
        self.results_table = ttk.Treeview(results_frame, columns=columns, show='headings', height=10)
        for col, w in zip(columns, (120, 100, 80, 300, 200, 150, 60)):
            self.results_table.heading(col, text=col)
            self.results_table.column(col, width=w)
        vsb = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_table.yview)
        hsb = ttk.Scrollbar(results_frame, orient="horizontal", command=self.results_table.xview)
        self.results_table.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.results_table.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        results_frame.grid_rowconfigure(0, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)

        log_frame = ttk.LabelFrame(right_panel, text="Лог процесса")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, height=6, state='disabled')
        self.log_text.pack(fill=tk.BOTH, expand=True)

    # ---------- Helpers ----------
    def _select_all(self):
        for var in self.category_vars.values():
            var.set(True)
        self._log("Все категории выбраны")

    def _deselect_all(self):
        for var in self.category_vars.values():
            var.set(False)
        self._log("Все категории сняты")

    def _log(self, msg: str):
        try:
            self.log_queue.put_nowait(('log', msg))
        except queue.Full:
            # drop excessive logs to keep UI responsive
            pass
        log_to_file(msg)

    def _info(self, text: str):
        if self.safe_ui.get():
            self._log(text)
            return
        try:
            messagebox.showinfo("Готово", text)
        except Exception:
            pass

    def _warn(self, text: str):
        if self.safe_ui.get():
            self._log(text)
            return
        try:
            messagebox.showwarning("Предупреждение", text)
        except Exception:
            pass

    def _error(self, text: str):
        if self.safe_ui.get():
            self._log(f"Ошибка: {text}")
            return
        try:
            messagebox.showerror("Ошибка", text)
        except Exception:
            pass

    def _append_log(self, message: str):
        self.log_text.configure(state='normal')
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state='disabled')

    def _update_stats_text(self):
        stats_by_category = defaultdict(int)
        for finding in self.all_findings:
            stats_by_category[finding['category']] += 1
        remaining = max(0, self.metrics['total_files'] - self.metrics['files_processed'])
        stats_text = (
            f"Загружено: {self.metrics['total_files']}  "
            f"Проверено: {self.metrics['files_processed']}  "
            f"Осталось: {remaining}  "
            f"Строк: {self.metrics['lines_scanned']}  "
            f"Найдено: {self.metrics['findings_total']}  "
            f"Good: {self.metrics['findings_good']}  "
            f"Bad: {self.metrics['findings_invalid']}\n"
        )
        if stats_by_category:
            for cat, count in sorted(stats_by_category.items()):
                stats_text += f"{cat}: {count}  "
        self.stats_text.configure(state='normal')
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(1.0, stats_text)
        self.stats_text.configure(state='disabled')
        if self.metrics['total_files']:
            self.progress_bar['value'] = (self.metrics['files_processed'] / self.metrics['total_files']) * 100

    def _add_results_batch(self, batch):
        # cap UI rows to avoid freezes
        try:
            limit = int(self.ui_rows_limit_var.get()) if self.ui_rows_limit_var.get().strip() else 0
        except Exception:
            limit = 0
        if not hasattr(self, 'ui_rows_added'):
            self.ui_rows_added = 0
        for finding, filename in batch:
            account = finding.get('account', '')
            value = finding['value']
            if len(value) > 60:
                value = value[:60] + '...'
            if limit and self.ui_rows_added >= limit:
                # Only count further findings, do not insert to UI
                continue
            values = (
                finding['category'], finding['type'], finding.get('status', ''), value, account,
                os.path.basename(filename), finding.get('line', '')
            )
            self.results_table.insert('', 0, values=values)
            self.ui_rows_added += 1

    def _tick_queues(self):
        # drain limited logs per tick
        log_processed = 0
        try:
            while log_processed < 100:
                msg_type, data = self.log_queue.get_nowait()
                log_processed += 1
                if msg_type == 'log':
                    self._append_log(data)
                elif msg_type == 'status':
                    self.status_var.set(data)
                elif msg_type == 'complete':
                    self._on_complete()
        except queue.Empty:
            pass

        # drain limited results per tick (batched inserts)
        try:
            batch = []
            while len(batch) < 20:
                item = self.result_queue.get_nowait()
                batch.append(item)
            if batch:
                self._add_results_batch(batch)
        except queue.Empty:
            if 'batch' in locals() and batch:
                self._add_results_batch(batch)

        # drain limited stats signals
        stats_processed = 0
        try:
            while stats_processed < 50:
                self.stats_queue.get_nowait()
                stats_processed += 1
        except queue.Empty:
            pass
        # always refresh stats for heartbeat
        self._update_stats_text()

        self.root.after(100, self._tick_queues)

    # ---------- File loading ----------
    def _load_file(self):
        file_paths = filedialog.askopenfilenames(
            title="Выберите файлы для парсинга",
            filetypes=[
                ("All supported", "*.txt *.log *.eml *.json *.zip"),
                ("Text files", "*.txt"),
                ("Log files", "*.log"),
                ("Email files", "*.eml"),
                ("JSON files", "*.json"),
                ("ZIP archives", "*.zip"),
                ("All files", "*.*")
            ]
        )
        if not file_paths:
            return
        self.current_results = list(file_paths)
        self._log(f"Загружено {len(file_paths)} файл(ов)")
        messagebox.showinfo("Готово", f"Загружено {len(file_paths)} файл(ов). Нажмите 'Старт' для начала парсинга.")

    def _load_folder(self):
        if self.loading_files:
            return
        folder_path = filedialog.askdirectory(title="Выберите папку для парсинга")
        if not folder_path:
            return
        # also reflect in manual entry for clarity
        try:
            self.path_var.set(folder_path)
        except Exception:
            pass
        self.loading_files = True
        # disable controls during scan
        try:
            self.btn_folder.config(state=tk.DISABLED)
            self.btn_file.config(state=tk.DISABLED)
            self.start_btn.config(state=tk.DISABLED)
        except Exception:
            pass
        self._log(f"Сканирую список файлов в: {folder_path} (это может занять время)...")
        self.status_var.set("Сканирование списка файлов...")
        def worker():
            files = []
            # read limit early
            try:
                limit_n = int(self.limit_var.get()) if self.limit_var.get().strip() else 0
            except Exception:
                limit_n = 0
            counted = 0
            try:
                for root, dirnames, filenames in os.walk(folder_path, topdown=True):
                    # Optional: skip system-like directories quickly (speeds up на больших деревьях)
                    # dirnames[:] = [d for d in dirnames if d not in ('node_modules', '.git', '__pycache__')]
                    for filename in filenames:
                        try:
                            files.append(os.path.join(root, filename))
                            counted += 1
                            if counted % 5000 == 0:
                                self._log(f"Просканировано путей: {counted}...")
                                self.stats_queue.put(True)
                            if limit_n > 0 and len(files) >= limit_n:
                                raise StopIteration
                        except PermissionError:
                            continue
            except StopIteration:
                pass
            except Exception as e:
                self._log(f"Ошибка обхода папки: {e}")
            def finalize():
                self.current_results = files
                self.metrics['total_files'] = len(files)
                self._log(f"Найдено {len(files)} файл(ов) в папке {os.path.basename(folder_path)}")
                self.status_var.set("Готов к запуску")
                try:
                    messagebox.showinfo("Готово", f"Найдено {len(files)} файл(ов) в папке. Нажмите 'Старт' для начала парсинга.")
                except Exception:
                    pass
                # re-enable controls
                try:
                    self.btn_folder.config(state=tk.NORMAL)
                    self.btn_file.config(state=tk.NORMAL)
                    self.start_btn.config(state=tk.NORMAL)
                except Exception:
                    pass
                self.loading_files = False
                self.stats_queue.put(True)
            self.root.after(0, finalize)
        threading.Thread(target=worker, daemon=True).start()

    def _normalize_folder_path(self, p: str) -> str:
        p = os.path.expanduser(p)
        # Map common aliases
        if p.lower() in ("desktop", "~/desktop"):
            p = os.path.join(os.path.expanduser("~"), "Desktop")
        # OneDrive Desktop redirection often lives under OneDrive\Desktop
        if not os.path.isdir(p):
            alt = os.path.join(os.path.expanduser("~"), "OneDrive", "Desktop")
            if os.path.isdir(alt):
                p = alt
        # Windows long path prefix
        if os.name == 'nt' and not p.startswith('\\\\?\\') and len(p) > 240:
            p = '\\\\?\\' + p
        return os.path.normpath(p)

    def _load_folder_from_path(self):
        if self.loading_files:
            return
        raw = (self.path_var.get() or '').strip()
        if not raw:
            messagebox.showwarning("Ошибка", "Укажите путь к папке")
            return
        folder_path = self._normalize_folder_path(raw)
        if not os.path.isdir(folder_path):
            messagebox.showerror("Ошибка", f"Папка недоступна: {raw}")
            return
        self.loading_files = True
        try:
            self.btn_folder.config(state=tk.DISABLED)
            self.btn_file.config(state=tk.DISABLED)
            self.start_btn.config(state=tk.DISABLED)
        except Exception:
            pass
        self._log(f"Сканирую список файлов (из поля): {folder_path}")
        self.status_var.set("Сканирование списка файлов...")
        def worker():
            files = []
            try:
                try:
                    limit_n = int(self.limit_var.get()) if self.limit_var.get().strip() else 0
                except Exception:
                    limit_n = 0
                counted = 0
                for root, dirnames, filenames in os.walk(folder_path, topdown=True):
                    for filename in filenames:
                        try:
                            files.append(os.path.join(root, filename))
                            counted += 1
                            if counted % 5000 == 0:
                                self._log(f"Просканировано путей: {counted}...")
                                self.stats_queue.put(True)
                            if limit_n > 0 and len(files) >= limit_n:
                                raise StopIteration
                        except PermissionError:
                            continue
            except StopIteration:
                pass
            except Exception as e:
                self._log(f"Ошибка обхода папки: {e}")
            def finalize():
                self.current_results = files
                self.metrics['total_files'] = len(files)
                self._log(f"Найдено {len(files)} файл(ов) в выбранном пути")
                self.status_var.set("Готов к запуску")
                try:
                    messagebox.showinfo("Готово", f"Найдено {len(files)} файл(ов). Нажмите 'Старт'.")
                except Exception:
                    pass
                try:
                    self.btn_folder.config(state=tk.NORMAL)
                    self.btn_file.config(state=tk.NORMAL)
                    self.start_btn.config(state=tk.NORMAL)
                except Exception:
                    pass
                self.loading_files = False
                self.stats_queue.put(True)
            self.root.after(0, finalize)
        threading.Thread(target=worker, daemon=True).start()

    def _create_test_data(self):
        base = os.path.join(os.path.dirname(__file__), 'test_data')
        try:
            os.makedirs(base, exist_ok=True)
            sub1 = os.path.join(base, 'a')
            sub2 = os.path.join(base, 'b', 'c')
            os.makedirs(sub1, exist_ok=True)
            os.makedirs(sub2, exist_ok=True)
            files = {
                os.path.join(base, 'root.txt'): "hello test user@example.com\nno match here\n",
                os.path.join(sub1, 'a1.log'): "password: qwerty\nline2\n",
                os.path.join(sub2, 'c1.txt'): "contact admin@mail.com\n",
                os.path.join(sub2, 'bin.bin'): b"\x00\x01\x02",
            }
            for p, content in files.items():
                if isinstance(content, bytes):
                    with open(p, 'wb') as fb:
                        fb.write(content)
                else:
                    with open(p, 'w', encoding='utf-8') as fw:
                        fw.write(content)
            # preload
            file_list = []
            for root, _, names in os.walk(base):
                for n in names:
                    file_list.append(os.path.join(root, n))
            self.current_results = file_list
            self.metrics['total_files'] = len(file_list)
            self._log(f"Тестовые файлы готовы: {len(file_list)} | {base}")
            try:
                messagebox.showinfo("Готово", f"Тестовые файлы готовы: {len(file_list)}. Нажмите 'Старт'.")
            except Exception:
                pass
            self.stats_queue.put(True)
        except Exception as e:
            self._log(f"Ошибка создания тестовых данных: {e}")

    # ---------- Run ----------
    def _start(self):
        if self.is_running:
            # ignore repeated clicks while running
            self._log("Парсинг уже запущен")
            return
        if not self.current_results:
            messagebox.showwarning("Ошибка", "Сначала загрузите файл или папку!")
            return
        selected_categories = [cat for cat, var in self.category_vars.items() if var.get()]
        if not selected_categories:
            messagebox.showwarning("Ошибка", "Выберите хотя бы одну категорию для парсинга!")
            return
        # apply limit if provided
        try:
            n = int(self.limit_var.get()) if self.limit_var.get().strip() else 0
        except Exception:
            n = 0
        if n > 0 and len(self.current_results) > n:
            self.current_results = self.current_results[:n]
            self._log(f"Ограничение: берём первые {n} файлов")
            self.metrics['total_files'] = n
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.is_running = True
        self.stop_requested = False
        self.log_queue.put(('status', "Парсинг выполняется..."))
        self.metrics = {
            'files_processed': 0,
            'total_files': len(self.current_results),
            'lines_scanned': 0,
            'findings_total': 0,
            'findings_good': 0,
            'findings_invalid': 0,
        }
        self.all_findings = []
        self.seen_hashes = set()
        self.progress_bar['value'] = 0
        for item in self.results_table.get_children():
            self.results_table.delete(item)
        self._update_stats_text()
        self._log(f"=== Начало парсинга {len(self.current_results)} файл(ов) с {self.threads_var.get()} потоками ===")
        self._log(f"Режим: {'seq' if self.sequential.get() else 'pool'} | категорий: {len([c for c,v in self.category_vars.items() if v.get()])} | ключевые слова: '{self.keyword_var.get()}'")
        thread = threading.Thread(target=self._parse_files, daemon=True)
        thread.start()

    def _stop(self):
        self.stop_requested = True
        self._log("Запрошена остановка парсинга...")

    # ---------- Parsing ----------
    def _parse_files(self):
        try:
            num_threads = max(1, int(self.threads_var.get()))
            selected_categories = [cat for cat, var in self.category_vars.items() if var.get()]
            keywords = [k.strip().lower() for k in self.keyword_var.get().split(',') if k.strip()]
            if self.sequential.get():
                total = len(self.current_results)
                for idx, file_path in enumerate(self.current_results, 1):
                    if self.stop_requested:
                        self._log("Парсинг остановлен пользователем")
                        break
                    try:
                        log_msg = self._process_and_scan_file(file_path, selected_categories, keywords)
                        if log_msg:
                            self._log(f"[{idx}/{total}] {log_msg}")
                    except Exception as e:
                        self._log(f"Ошибка обработки {os.path.basename(file_path)}: {e}")
                    finally:
                        self.metrics['files_processed'] += 1
                        if idx % 20 == 0:
                            self._log(f"Продвинулись: {idx}/{total} файлов")
                        self.stats_queue.put(True)
            else:
                with ThreadPoolExecutor(max_workers=num_threads) as executor:
                    futures = {executor.submit(self._process_and_scan_file, file_path, selected_categories, keywords): file_path
                               for file_path in self.current_results}
                    for i, future in enumerate(as_completed(futures), 1):
                        if self.stop_requested:
                            self._log("Парсинг остановлен пользователем")
                            break
                        file_path = futures[future]
                        try:
                            log_msg = future.result()
                            if log_msg:
                                if i % 20 == 0:
                                    self._log(f"Готово файлов: {i}")
                                self._log(log_msg)
                        except Exception as e:
                            self._log(f"Ошибка обработки {os.path.basename(file_path)}: {e}")
                        finally:
                            self.metrics['files_processed'] += 1
                            self.stats_queue.put(True)
            self._log("=== Парсинг завершён ===")
            self.log_queue.put(('complete', None))
        except Exception as e:
            self._log(f"Ошибка при парсинге: {e}")
            self.log_queue.put(('complete', None))

    def _process_and_scan_file(self, file_path, selected_categories, keywords):
        p = Path(file_path)
        log_msg = f"Обработка: {p.name}"
        ext = p.suffix.lower()
        try:
            if ext == '.zip':
                for member, line in iter_zip_members_text(p):
                    if self.stop_requested:
                        break
                    self._scan_line(line, member, selected_categories, keywords)
            elif ext == '.eml':
                for line in iter_eml_text(p):
                    if self.stop_requested:
                        break
                    self._scan_line(line, str(p), selected_categories, keywords)
            elif ext == '.json':
                # Scan JSON as text line-by-line (avoids heavy json.load)
                for i, line in enumerate(iter_text_lines_from_path(p) or [], 1):
                    if self.stop_requested:
                        break
                    self._scan_line(line, str(p), selected_categories, keywords, line_no=i)
            else:
                for i, line in enumerate(iter_text_lines_from_path(p) or [], 1):
                    if self.stop_requested:
                        break
                    self._scan_line(line, str(p), selected_categories, keywords, line_no=i)
        except Exception as e:
            log_to_file(f"Ошибка чтения {p.name}: {e}")
        return log_msg

    def _scan_line(self, line: str, filename: str, selected_categories, keywords, line_no: int = None):
        if not line:
            return
        if keywords:
            ll = line.lower()
            if not any(k in ll for k in keywords):
                return
        # stats: line scanned
        self.metrics['lines_scanned'] += 1
        if self.metrics['lines_scanned'] % 50 == 0:
            self.stats_queue.put(True)
        account_email = ''
        m = EMAIL_REGEX.search(line)
        if m:
            account_email = m.group(0)
        for category in selected_categories:
            patterns = COMPILED_PATTERNS.get(category, [])
            for pat in patterns:
                for match in pat['regex'].finditer(line):
                    value = match.group(0)
                    fh = hashlib.md5((category + '|' + pat['name'] + '|' + value).encode()).hexdigest()
                    if fh in self.seen_hashes:
                        continue
                    self.seen_hashes.add(fh)
                    status = validate_finding(category, pat['name'], value)
                    finding = {
                        'category': category,
                        'type': pat['name'],
                        'status': status,
                        'value': value,
                        'line': line_no if line_no is not None else '',
                        'account': account_email,
                        'filename': filename,
                    }
                    # global counters
                    self.metrics['findings_total'] += 1
                    if status == 'good':
                        self.metrics['findings_good'] += 1
                    else:
                        self.metrics['findings_invalid'] += 1
                    # push immediately for UI
                    self.result_queue.put((finding, filename))
                    self.all_findings.append(finding)
                    # periodic stats refresh
                    if self.metrics['findings_total'] % 20 == 0:
                        self.stats_queue.put(True)

    # ---------- Completion ----------
    def _on_complete(self):
        self.is_running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        status_msg = f"Готово. Обработано файлов: {self.metrics['files_processed']}, найдено элементов: {len(self.all_findings)}"
        self.status_var.set(status_msg)
        self.progress_bar['value'] = 100
        if not self.stop_requested:
            messagebox.showinfo("Готово", f"Парсинг завершён!\n\nОбработано файлов: {self.metrics['files_processed']}\nНайдено элементов: {len(self.all_findings)}")

    # ---------- Save / Export ----------
    def _save_results(self):
        if not self.all_findings:
            messagebox.showwarning("Предупреждение", "Нет данных для сохранения")
            return
        try:
            with open(FOUND_TXT, 'w', encoding='utf-8') as f:
                f.write("=== РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ ===\n\n")
                for finding in self.all_findings:
                    f.write(f"[{finding['category']} - {finding['type']}]\n")
                    f.write(f"Значение: {finding['value']}\n")
                    f.write(f"Аккаунт: {finding.get('account', 'N/A')}\n")
                    f.write(f"Файл: {os.path.basename(finding.get('filename', 'N/A'))}\n")
                    f.write(f"Строка: {finding.get('line', 'N/A')}\n")
                    f.write("-" * 60 + "\n\n")
            with open(FOUND_JSON, 'w', encoding='utf-8') as f:
                json.dump(self.all_findings, f, ensure_ascii=False, indent=2)
            with open(FOUND_CSV, 'w', encoding='utf-8', newline='') as f:
                fieldnames = ['category', 'type', 'value', 'account', 'filename', 'line']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for finding in self.all_findings:
                    writer.writerow(finding)
            messagebox.showinfo("Успех", f"Результаты сохранены:\n{FOUND_TXT}\n{FOUND_JSON}\n{FOUND_CSV}")
            self._log(f"Результаты сохранены в {RESULTS_DIR}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить результаты: {e}")

    def _save_by_accounts(self):
        if not self.all_findings:
            messagebox.showwarning("Предупреждение", "Нет данных для сохранения")
            return
        folder_path = filedialog.askdirectory(title="Выберите папку для сохранения аккаунтов")
        if not folder_path:
            return
        try:
            by_acc = defaultdict(list)
            for fnd in self.all_findings:
                acc = fnd.get('account', 'unknown') or 'unknown'
                by_acc[acc].append(fnd)
            out_dir = os.path.join(folder_path, f"accounts_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            os.makedirs(out_dir, exist_ok=True)
            for account, findings in by_acc.items():
                safe = re.sub(r'[^\w\-_\.]', '_', account)
                txt_file = os.path.join(out_dir, f"{safe}.txt")
                with open(txt_file, 'w', encoding='utf-8') as f:
                    f.write(f"=== АККАУНТ: {account} ===\n")
                    f.write(f"Найдено элементов: {len(findings)}\n")
                    f.write("=" * 60 + "\n\n")
                    for fi in findings:
                        f.write(f"[{fi['category']} - {fi['type']}]\n{fi['value']}\n")
                        f.write(f"Файл: {os.path.basename(fi.get('filename', 'N/A'))}\n")
                        f.write(f"Строка: {fi.get('line', 'N/A')}\n\n")
                json_file = os.path.join(out_dir, f"{safe}.json")
                with open(json_file, 'w', encoding='utf-8') as f:
                    json.dump(findings, f, ensure_ascii=False, indent=2)
                csv_file = os.path.join(out_dir, f"{safe}.csv")
                with open(csv_file, 'w', encoding='utf-8', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['category', 'type', 'value', 'account', 'filename', 'line'], extrasaction='ignore')
                    writer.writeheader()
                    for fi in findings:
                        writer.writerow(fi)
            messagebox.showinfo("Успех", f"Данные по аккаунтам сохранены в: {out_dir}")
            self._log(f"Сохранены аккаунты в {out_dir}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка сохранения: {e}")
            self._log(f"Ошибка сохранения аккаунтов: {e}")

    def _download_logs(self):
        if not os.path.exists(LOG_PATH):
            messagebox.showwarning("Предупреждение", "Лог файл не найден")
            return
        save_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("All files", "*.*")],
            initialfile=f"scanner_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        if save_path:
            try:
                import shutil
                shutil.copy(LOG_PATH, save_path)
                messagebox.showinfo("Успех", f"Логи сохранены в:\n{save_path}")
                self._log(f"Логи скачаны: {save_path}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось скопировать логи: {e}")

    def _clear(self):
        for item in self.results_table.get_children():
            self.results_table.delete(item)
        self.all_findings = []
        self.seen_hashes = set()
        self._log("Таблица очищена")
        self._update_stats_text()

# ---------- Entrypoint ----------
def main():
    root = tk.Tk()
    app = ScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    print("=" * 60)
    print("🔍 Сканер конфиденциальных данных - Optimized GUI Application")
    print("=" * 60)
    print("Запуск приложения...")
    print("=" * 60)
    main()
