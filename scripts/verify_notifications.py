"""Verify signed retry transport against a loopback-only disposable HTTP sink."""
import argparse
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
PROGRAM=r'''
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from threading import Thread
import hashlib,hmac,json,secrets,time
from porygon_api.notifications import Destination
from porygon_api.notification_worker import send_webhook
key=secrets.token_urlsafe(48);received=[];mode=[503]
class Handler(BaseHTTPRequestHandler):
 def do_POST(self):
  payload=self.rfile.read(int(self.headers['Content-Length']));stamp=self.headers['X-Porygon-Timestamp']
  expected='sha256='+hmac.new(key.encode(),stamp.encode()+b'.'+payload,hashlib.sha256).hexdigest()
  assert hmac.compare_digest(expected,self.headers['X-Porygon-Signature']) and abs(time.time()-int(stamp))<30
  received.append(self.headers['X-Porygon-Delivery-ID']);self.send_response(mode[0]);self.end_headers()
 def log_message(self,*args):pass
server=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=Thread(target=server.serve_forever,daemon=True);thread.start()
destination=Destination(destination_id='local-verifier',url=f'http://127.0.0.1:{server.server_port}/events',allow_loopback=True,hmac_secret=key)
try:
 try:send_webhook(destination,'stable-test-id',b'{"type":"local-fixture"}',timeout=2)
 except ValueError:pass
 else:raise AssertionError('503 must refuse acknowledgement')
 mode[0]=204;send_webhook(destination,'stable-test-id',b'{"type":"local-fixture"}',timeout=2)
 assert received==['stable-test-id','stable-test-id']
 mode[0]=302
 try:send_webhook(destination,'redirect-test-id',b'{}',timeout=2)
 except ValueError:pass
 else:raise AssertionError('Redirect must not count as delivery')
 print(json.dumps({'passed':True,'hmac':'verified','stable_retry_id':'verified','redirects':'refused','destination':'loopback-only','external_messages':0}))
finally:server.shutdown();server.server_close();thread.join(timeout=3)
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--local-sink',action='store_true',required=True);parser.parse_args()
    result=subprocess.run(['docker','compose','exec','-T','backend','python','-c',PROGRAM],cwd=ROOT,capture_output=True,text=True,timeout=30,check=True)
    print(json.dumps(json.loads(result.stdout)))


if __name__=='__main__':main()
