import os, tempfile, unittest, sqlite3, json
from pathlib import Path
os.environ['SOC_ANALYZER_HOME'] = tempfile.mkdtemp(prefix='localsoc822_')
import app

class URIParseTests(unittest.TestCase):
    def test_invoice_uri_decomposition(self):
        uri='/invoices/search?invoice_id=118824252&site_id=MeliCO&authtoken=ATUSER-ID-toolsuser'
        d=app.parse_uri_dimensions(uri)
        self.assertEqual(d['endpoint'],'/invoices/search')
        self.assertEqual(d['invoice_id'],'118824252')
        self.assertEqual(d['site_id'],'MeliCO')
        self.assertEqual(d['identity'],'toolsuser')
        self.assertEqual(len(d['auth_token_fingerprint']),64)

    def test_encoded_and_repeated_parameters(self):
        d=app.parse_uri_dimensions('/x?a=1&invoice_id=ABC%201&invoice_id=ABC2&site_id=Meli%20CO&authtoken=ATUSER-ID-User_1')
        self.assertEqual(d['invoice_id'],'ABC 1')
        self.assertEqual(d['site_id'],'Meli CO')
        self.assertEqual(d['identity'],'user_1')
        self.assertNotIn('ATUSER-ID-User_1', json.dumps(d))

    def test_normalize_record(self):
        e=app.normalize_record({'http_uri':'/invoices/search?invoice_id=42&site_id=MeliCO&authtoken=ATUSER-ID-toolsuser','http_staus':'403','source_ip':'192.0.2.1','http_method':'GET'},'csv',7,'raw')
        self.assertEqual(e['username'],'toolsuser')
        self.assertEqual(e['status_code'],'403')
        self.assertEqual(e['endpoint'],'/invoices/search')
        self.assertEqual(e['invoice_id'],'42')

if __name__=='__main__': unittest.main()
