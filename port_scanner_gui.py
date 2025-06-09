# -*- coding: utf-8 -*-
import sys
import subprocess
import socket
import requests
import re
import json
import threading
import ctypes

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QListWidget, QTextBrowser, QLabel, QTabWidget, QLineEdit, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QObject
from PyQt6.QtGui import QFont

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Yönetici kontrolü ve kendini yönetici olarak başlatma
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()

# Yardımcı Fonksiyonlar

def run_subprocess(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, shell=True)
        try:
            return result.stdout.decode("utf-8")
        except UnicodeDecodeError:
            return result.stdout.decode("windows-1254", errors="replace")
    except Exception as e:
        return f"Hata: {e}"

def get_listening_ports_and_pids():
    output = run_subprocess('netstat -aon')
    port_pid_map = {}
    for line in output.splitlines():
        if "LISTENING" in line:
            parts = line.split()
            if len(parts) >= 5:
                local_address = parts[1]
                pid = parts[4]
                match = re.search(r':(\d+)$', local_address)
                if match:
                    port = int(match.group(1))
                    port_pid_map[port] = pid
    return port_pid_map

def get_process_name(pid):
    output = run_subprocess(f'tasklist /FI "PID eq {pid}"')
    lines = output.splitlines()
    if len(lines) >= 4:
        return lines[3].split()[0]
    return "Bilinmiyor"

def get_services_for_pid(pid):
    try:
        ps_cmd = (
            f"powershell -NoProfile -Command \""
            f"$OutputEncoding = [System.Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            f"Get-WmiObject Win32_Service | "
            f"Where-Object {{$_.ProcessId -eq {pid}}} | "
            f"Select-Object Name,DisplayName,PathName,Description | "
            f"ConvertTo-Json -Compress -Depth 3\""
        )
        output = run_subprocess(ps_cmd)
        services = json.loads(output)
        if isinstance(services, dict):
            services = [services]
        return services
    except Exception:
        return []

def is_port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except Exception:
        return False

def analyze_http_https(port):
    urls = [
        ("http", f"http://127.0.0.1:{port}"),
        ("https", f"https://127.0.0.1:{port}")
    ]
    for proto, url in urls:
        try:
            response = requests.get(url, timeout=3, verify=False)
            return f"✅ {proto.upper()} Durum: {response.status_code}, Server: {response.headers.get('Server', 'Bilinmiyor')}"
        except requests.exceptions.RequestException:
            continue
    return "❌ HTTP/HTTPS bağlantısı sağlanamadı"

def banner_grab_socket(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(("127.0.0.1", port))
        probes = [
            b"HEAD / HTTP/1.0\r\n\r\n",
            b"\r\n",
            b"\x00",
            b"SMB2",
            b"RDP",
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        ]
        banner = ""
        for p in probes:
            try:
                sock.sendall(p)
                data = sock.recv(4096).decode(errors='replace')
                banner += f"Probe: {p} -> Banner:\n{data}\n\n"
            except Exception:
                continue
        sock.close()
        return banner.strip()
    except Exception:
        return "Banner alınamadı"

def kill_process(pid):
    try:
        output = run_subprocess(f'taskkill /PID {pid} /F')
        if "Başarıyla" in output or "SUCCESS" in output.upper():
            return f"✅ PID {pid} başarıyla sonlandırıldı."
        return output.strip()
    except Exception as e:
        return f"Hata: {e}"

def block_port_firewall(port):
    try:
        cmd = f'netsh advfirewall firewall add rule name="Block Port {port}" dir=in action=block protocol=TCP localport={port}'
        output = run_subprocess(cmd)
        if "OK" in output.upper():
            return f"✅ Port {port} engellendi."
        return output.strip()
    except Exception as e:
        return f"Hata: {e}"

# PyQt6 Threading için sinyal sınıfı

class WorkerSignals(QObject):
    finished = pyqtSignal()
    error = pyqtSignal(str)
    result = pyqtSignal(dict)
    log = pyqtSignal(str)

class ScanWorker(threading.Thread):
    def __init__(self, signals):
        super().__init__()
        self.signals = signals

    def run(self):
        try:
            self.signals.log.emit("🎧 Windows'ta dinleyen portlar ve PID'ler taranıyor...")
            port_pid_map = get_listening_ports_and_pids()
            if not port_pid_map:
                self.signals.error.emit("⚠️ Dinleyen port bulunamadı.")
                self.signals.finished.emit()
                return
            self.signals.log.emit(f"🎯 Bulunan dinleyen portlar: {list(port_pid_map.keys())}")
            for port, pid in port_pid_map.items():
                self.signals.log.emit(f"🔢 Port {port} - PID: {pid} - Süreç: {get_process_name(pid)}")
                port_open = is_port_open(port)
                services = get_services_for_pid(pid)
                if not services:
                    services = [{"Name": "Servis bulunamadı", "DisplayName": "", "PathName": "", "Description": ""}]
                http_status = analyze_http_https(port) if port_open else "Port kapalı"
                banner = banner_grab_socket(port) if port_open else "Port kapalı, banner alınamadı"
                data = {
                    "port": port,
                    "pid": pid,
                    "process": get_process_name(pid),
                    "port_open": port_open,
                    "services": services,
                    "http_status": http_status,
                    "banner": banner,
                }
                self.signals.result.emit(data)
            self.signals.finished.emit()
        except Exception as e:
            self.signals.error.emit(f"Hata: {e}")

# Ana GUI

class PortScannerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔍 Siyah Muhafız Port Scanner v2.1")
        self.resize(1000, 700)

        self.layout = QHBoxLayout()
        self.setLayout(self.layout)

        # Sol taraf
        self.left_layout = QVBoxLayout()
        self.btn_scan = QPushButton("🚀 Tara")
        self.btn_scan.clicked.connect(self.start_scan)
        self.port_list = QListWidget()
        self.port_list.itemSelectionChanged.connect(self.on_port_selected)
        self.left_layout.addWidget(self.btn_scan)
        self.left_layout.addWidget(QLabel("🎯 Dinleyen Portlar:"))
        self.left_layout.addWidget(self.port_list)

        self.btn_kill_pid = QPushButton("❌ PID Sonlandır")
        self.btn_kill_pid.clicked.connect(self.kill_selected_pid)
        self.btn_block_port = QPushButton("🚫 Portu Engelle")
        self.btn_block_port.clicked.connect(self.block_selected_port)
        self.btn_tasklist_pid = QPushButton("🔎 PID Tasklist Ara")
        self.btn_tasklist_pid.clicked.connect(self.find_pid_in_tasklist)

        # Yeni buton: PID için servisleri göster
        self.btn_pid_services = QPushButton("🔧 PID Servisleri")
        self.btn_pid_services.clicked.connect(self.show_pid_services)

        self.left_layout.addWidget(self.btn_kill_pid)
        self.left_layout.addWidget(self.btn_block_port)
        self.left_layout.addWidget(self.btn_tasklist_pid)
        self.left_layout.addWidget(self.btn_pid_services)

        # Sağ taraf: Tab widget ile detayları bölüyoruz
        self.right_layout = QVBoxLayout()
        self.tabs = QTabWidget()

        # Port Detayları Sekmesi
        self.tab_port_details = QTextBrowser()
        self.tab_port_details.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4;")
        self.tab_port_details.setFont(QFont("Segoe UI", 10))
        self.tabs.addTab(self.tab_port_details, "📄 Port Detayları")

        # Servis Detayları Sekmesi
        self.tab_service_details = QTextBrowser()
        self.tab_service_details.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4;")
        self.tab_service_details.setFont(QFont("Segoe UI", 10))
        self.tabs.addTab(self.tab_service_details, "🛠️ Servis Detayları")

        # PID Tasklist Arama Sekmesi (YENİ)
        self.tab_pid_tasklist = QWidget()
        self.pid_tasklist_layout = QVBoxLayout()
        self.tab_pid_tasklist.setLayout(self.pid_tasklist_layout)

        self.pid_input = QLineEdit()
        self.pid_input.setPlaceholderText("PID girin veya listeden port seçip otomatik alabilirsiniz")
        self.btn_pid_search = QPushButton("🔍 PID Tasklist")
        self.btn_pid_search.clicked.connect(self.search_pid_tasklist)
        self.pid_tasklist_output = QTextBrowser()
        self.pid_tasklist_output.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4;")
        self.pid_tasklist_output.setFont(QFont("Consolas", 10))

        self.pid_tasklist_layout.addWidget(self.pid_input)
        self.pid_tasklist_layout.addWidget(self.btn_pid_search)
        self.pid_tasklist_layout.addWidget(self.pid_tasklist_output)

        self.tabs.addTab(self.tab_pid_tasklist, "📋 PID Tasklist")

        # PID Servisleri Sekmesi (YENİ)
        self.tab_pid_services = QTextBrowser()
        self.tab_pid_services.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4;")
        self.tab_pid_services.setFont(QFont("Consolas", 10))
        self.tabs.addTab(self.tab_pid_services, "🔧 PID Servisleri")

        self.right_layout.addWidget(self.tabs)

        self.layout.addLayout(self.left_layout, 1)
        self.layout.addLayout(self.right_layout, 3)

        self.signals = WorkerSignals()
        self.signals.result.connect(self.add_port_result)
        self.signals.log.connect(self.log_message)
        self.signals.error.connect(self.error_message)
        self.signals.finished.connect(self.scan_finished)

        self.scan_thread = None

        self.current_scan_results = {}

    def start_scan(self):
        self.port_list.clear()
        self.tab_port_details.clear()
        self.tab_service_details.clear()
        self.pid_tasklist_output.clear()
        self.tab_pid_services.clear()
        self.pid_input.clear()
        self.current_scan_results = {}

        self.btn_scan.setEnabled(False)
        self.scan_thread = ScanWorker(self.signals)
        self.scan_thread.start()

    def add_port_result(self, data):
        port = data["port"]
        pid = data["pid"]
        process = data["process"]
        port_open = data["port_open"]

        line = f"🔌 Port {port} - 🆔 PID {pid} - 🖥️ {process} - {'🟢 Açık' if port_open else '🔴 Kapalı'}"
        self.port_list.addItem(line)
        self.current_scan_results[port] = data

    def on_port_selected(self):
        selected_items = self.port_list.selectedItems()
        if not selected_items:
            return
        line = selected_items[0].text()
        pid_match = re.search(r"PID (\d+)", line)
        if pid_match:
            pid = pid_match.group(1)
            # PID Tasklist input alanını otomatik doldur
            self.pid_input.setText(pid)
            # Aynı zamanda port ve pid bilgilerini detay tablarında göster
            self.show_port_details()
            self.show_pid_services()

    def show_port_details(self):
        selected_items = self.port_list.selectedItems()
        if not selected_items:
            return
        line = selected_items[0].text()
        port_match = re.search(r"Port (\d+)", line)
        if not port_match:
            return
        port = int(port_match.group(1))
        if port not in self.current_scan_results:
            return
        data = self.current_scan_results[port]

        port_details = (
            f"<b>🔌 Port:</b> {data['port']}<br>"
            f"<b>🆔 PID:</b> {data['pid']}<br>"
            f"<b>🖥️ Süreç:</b> {data['process']}<br>"
            f"<b>Durum:</b> {'🟢 Açık' if data['port_open'] else '🔴 Kapalı'}<br><br>"
            f"<b>🌐 HTTP/HTTPS Analizi:</b><br>{data['http_status']}<br><br>"
            f"<b>📢 Banner Bilgisi:</b><br><pre>{data['banner']}</pre>"
        )
        self.tab_port_details.setHtml(port_details)

        services = data["services"]
        services_str = "<b>🛠️ Bağlı Servisler:</b><br>"
        for s in services:
            services_str += (
                f"<b>Ad:</b> {s.get('Name', '')} <br>"
                f"<b>Gösterim Adı:</b> {s.get('DisplayName', '')} <br>"
                f"<b>Yol:</b> {s.get('PathName', '')} <br>"
                f"<b>Açıklama:</b> {s.get('Description', '')}<br><br>"
            )
        self.tab_service_details.setHtml(services_str)

    def kill_selected_pid(self):
        selected_items = self.port_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "⚠️ Uyarı", "❗ Önce listeden bir port seçin.")
            return
        line = selected_items[0].text()
        pid_match = re.search(r"PID (\d+)", line)
        if not pid_match:
            QMessageBox.warning(self, "❗ Hata", "PID bulunamadı.")
            return
        pid = pid_match.group(1)
        confirm = QMessageBox.question(
            self, "Onay",
            f"❗ PID {pid} sonlandırılsın mı?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            output = kill_process(pid)
            QMessageBox.information(self, "Sonuç", output)
            self.start_scan()

    def block_selected_port(self):
        selected_items = self.port_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "⚠️ Uyarı", "❗ Önce listeden bir port seçin.")
            return
        line = selected_items[0].text()
        port_match = re.search(r"Port (\d+)", line)
        if not port_match:
            QMessageBox.warning(self, "❗ Hata", "Port numarası bulunamadı.")
            return
        port = port_match.group(1)
        confirm = QMessageBox.question(
            self, "Onay",
            f"❗ Port {port} engellensin mi?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            output = block_port_firewall(port)
            QMessageBox.information(self, "Sonuç", output)

    def find_pid_in_tasklist(self):
        selected_items = self.port_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "⚠️ Uyarı", "❗ Önce listeden bir port seçin.")
            return
        line = selected_items[0].text()
        pid_match = re.search(r"PID (\d+)", line)
        if not pid_match:
            QMessageBox.warning(self, "❗ Hata", "PID bulunamadı.")
            return
        pid = pid_match.group(1)
        self.pid_input.setText(pid)
        self.search_pid_tasklist()

    def search_pid_tasklist(self):
        pid = self.pid_input.text().strip()
        if not pid.isdigit():
            QMessageBox.warning(self, "❗ Hata", "Lütfen geçerli bir PID girin.")
            return
        cmd = f'tasklist /svc /FI "PID eq {pid}"'
        result = run_subprocess(cmd)
        if not result.strip():
            result = f"❌ PID {pid} için servis bilgisi bulunamadı."
        self.pid_tasklist_output.setPlainText(result)
        self.tabs.setCurrentWidget(self.tab_pid_tasklist)

    def show_pid_services(self):
        selected_items = self.port_list.selectedItems()
        if not selected_items:
            return
        line = selected_items[0].text()
        pid_match = re.search(r"PID (\d+)", line)
        if not pid_match:
            return
        pid = pid_match.group(1)
        cmd = f'tasklist /svc /FI "PID eq {pid}"'
        result = run_subprocess(cmd)
        if not result.strip():
            result = f"❌ PID {pid} için servis bilgisi bulunamadı."
        self.tab_pid_services.clear()
        self.tab_pid_services.append(result)
        self.tabs.setCurrentWidget(self.tab_pid_services)

    def log_message(self, message):
        print(message)

    def error_message(self, message):
        QMessageBox.critical(self, "❌ Hata", message)
        self.btn_scan.setEnabled(True)

    def scan_finished(self):
        QMessageBox.information(self, "✅ Bilgi", "Tarama tamamlandı.")
        self.btn_scan.setEnabled(True)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PortScannerGUI()
    window.show()
    sys.exit(app.exec())
