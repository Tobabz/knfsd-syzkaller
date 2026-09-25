#!/usr/bin/env python3
import urllib.request
import html.parser
import json
from datetime import datetime

class TableParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_td = False
        self.current_row = []
        self.rows = []
        self.tables = []
        self.current_table = []
    def handle_starttag(self, tag, attrs):
        if tag == 'table': self.current_table = []
        elif tag == 'tr': self.current_row = []
        elif tag in ('td', 'th'): self.in_td = True
    def handle_endtag(self, tag):
        if tag == 'table': self.tables.append(self.current_table)
        elif tag == 'tr':
            if self.current_row:
                self.rows.append(self.current_row)
                self.current_table.append(self.current_row)
        elif tag in ('td', 'th'): self.in_td = False
    def handle_data(self, data):
        data = data.strip()
        if data and self.in_td: self.current_row.append(data)

def fetch_metrics():
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S KST')
    
    # Main page
    try:
        html = urllib.request.urlopen('http://localhost:56741', timeout=5).read().decode('utf-8', errors='ignore')
    except Exception as e:
        return {'error': str(e), 'time': now_str}
    
    p = TableParser()
    p.feed(html)
    
    stats = {}
    if len(p.tables) > 1:
        for row in p.tables[1]:
            if len(row) >= 2:
                stats[row[0]] = row[1]
                
    # Syscalls page
    try:
        html_sys = urllib.request.urlopen('http://localhost:56741/syscalls', timeout=5).read().decode('utf-8', errors='ignore')
        p_sys = TableParser()
        p_sys.feed(html_sys)
        
        nfs_calls = {}
        for r in p_sys.rows:
            if len(r) >= 4 and any('nfs' in r[0].lower() for _ in [1]):
                call_name = r[0].split()[0]
                nfs_calls[call_name] = {
                    'inputs': int(r[1]) if r[1].isdigit() else r[1],
                    'total': int(r[2]) if r[2].isdigit() else r[2],
                    'coverage': int(r[3]) if r[3].isdigit() else r[3]
                }
    except Exception as e:
        nfs_calls = {'error': str(e)}

    return {
        'time': now_str,
        'stats': stats,
        'nfs_calls': nfs_calls
    }

if __name__ == '__main__':
    data = fetch_metrics()
    print(json.dumps(data, indent=2))
