import csv, tempfile, unittest
from pathlib import Path
import app

class WAFTextCSVTests(unittest.TestCase):
    def test_delayed_header_and_blank_lines(self):
        content = [
            '2026-01-01T00:00,200,example.com,/invoices/search?invoice_id=1&authtoken=ATUSER-ID-alice,GET,-,UA,192.0.2.1',
            '2026-01-01T00:01,401,example.com,/invoices/search?invoice_id=2&authtoken=ATUSER-ID-bob,GET,-,UA,192.0.2.2',
            'timestamp,http_staus,http_host,http_uri,http_method,http_referer,http_user_agent,source_ip',
            '2026-01-01T00:02,403,example.com,/invoices/search?invoice_id=3&authtoken=ATUSER-ID-alice,GET,-,UA,192.0.2.1',
            '',
        ]
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'waf.txt'; p.write_text('\n'.join(content)+'\n',encoding='utf-8')
            self.assertEqual(app.detect_format(p.name, content[0]), 'csv')
            rows=list(app.iter_records(p,p.name))
        self.assertEqual(len(rows),3)
        self.assertEqual([r[0] for r in rows],[1,2,4])
        self.assertEqual([r[1]['src_ip'] for r in rows],['192.0.2.1','192.0.2.2','192.0.2.1'])
        self.assertEqual([r[1]['status_code'] for r in rows],['200','401','403'])
        self.assertEqual([r[1]['username'] for r in rows],['alice','bob','alice'])
        self.assertTrue(all(r[1]['uri'].startswith('/invoices/search') for r in rows))

if __name__=='__main__': unittest.main()
