import tkinter as tk
from tkinter import messagebox, filedialog
import requests
import csv
import json

class WalletAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title('Wallet Analyzer')

        # API Key Input
        self.api_key_label = tk.Label(root, text='Etherscan API Key:')
        self.api_key_label.pack()
        self.api_key_entry = tk.Entry(root)
        self.api_key_entry.pack()

        # Wallet Address Input
        self.wallet_label = tk.Label(root, text='Wallet Address:')
        self.wallet_label.pack()
        self.wallet_entry = tk.Entry(root)
        self.wallet_entry.pack()

        # Analyze Button
        self.analyze_button = tk.Button(root, text='Analyze', command=self.analyze_wallet)
        self.analyze_button.pack()

        # Results Text Box
        self.results_text = tk.Text(root, wrap='word', height=15, width=50)
        self.results_text.pack()

        # Export Button
        self.export_button = tk.Button(root, text='Export to CSV/JSON', command=self.export_data)
        self.export_button.pack()

    def analyze_wallet(self):
        api_key = self.api_key_entry.get()
        wallet_address = self.wallet_entry.get()

        if not api_key or not wallet_address:
            messagebox.showerror('Input Error', 'Please enter both API Key and Wallet Address.')
            return

        # Placeholder for wallet analysis
        self.results_text.delete('1.0', tk.END)
        self.results_text.insert(tk.END, f'Analyzing wallet: {wallet_address}\n')
        self.results_text.insert(tk.END, f'API Key: {api_key}\n')
        self.results_text.insert(tk.END, 'Analysis results appear here.\n')
        # Add Etherscan API calls for transaction history, NFT portfolio, etc.

    def export_data(self):
        data_to_export = self.results_text.get('1.0', tk.END).strip()
        file_type = simpledialog.askstring('File Type', 'Enter CSV or JSON:')

        if file_type.lower() == 'csv':
            self.save_to_csv(data_to_export)
        elif file_type.lower() == 'json':
            self.save_to_json(data_to_export)
        else:
            messagebox.showerror('Input Error', 'Please enter valid file type (CSV/JSON).')

    def save_to_csv(self, data):
        path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV files', '*.csv')])
        if path:
            with open(path, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Result'])
                for line in data.split('\n'):
                    writer.writerow([line])
            messagebox.showinfo('Export Successful', f'Data exported to {path}')

    def save_to_json(self, data):
        path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON files', '*.json')])
        if path:
            with open(path, mode='w') as file:
                json.dump({'results': data.split('\n')}, file, indent=4)
            messagebox.showinfo('Export Successful', f'Data exported to {path}')

if __name__ == '__main__':
    root = tk.Tk()
    app = WalletAnalyzerApp(root)
    root.mainloop()