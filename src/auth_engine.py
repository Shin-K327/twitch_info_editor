import certifi
from concurrent import futures
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import random
import time
from urllib.parse import urlencode, urlparse, parse_qs
import urllib3 as ul3
import webbrowser as wb

class WithTokenHTTPServer(HTTPServer):

    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.redirect_query = None


class TokenHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        rcvd_query = urlparse(self.path)[4]
        query_dict = parse_qs(rcvd_query)

        # リダイレクト時のURIに含まれてる文字列で処理を分岐させる
        if 'code' in query_dict.keys() and 'state' in query_dict.keys():
            self.send_response(200)

            # ToDO:htmlディレクトリ配下にあるスタイルシートファイルのパスを取る処理を追加する
            css_path = "os.pathジョインうんたら！"

            html = self._view_content('200.html').format(CSSPATH=css_path)

            if html is not None:
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(html.encode('utf-8'))
            else :
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write(b'Authentication Succeeded')

            self.server.redirect_query = query_dict
            self.server.server_close()

        elif 'error' in query_dict.keys():
            self.send_response(400)
            self.server.server_close()

    # バイナリ形式でHTMLファイルを返却するメソッド、サブディレクトリは直で書いてください
    def _view_content(self, filename):
        subdir = 'html'
        filepath = os.path.join(os.getcwd(), subdir, filename)
        try:
            with open(filepath, mode='r', encoding='utf_8') as f:
                return f.read()
        except FileNotFoundError as e:
            print(f'指定されたファイルが見つかりません。\n{e}')
            return None
        except TypeError as e:
            print(f'ファイルが読み込める形式ではありません。\n{e}')
            return None

class AuthCodeFlow(object):

    def __init__(self, auth_url, rcv_port: int, client_id, client_sec, *scope):

        self.auth_url = auth_url

        self.client_id = client_id
        self.client_sec = client_sec
        self.rcv_port = rcv_port
        self.scope = ' '.join(scope)

        # state生成用文字列、記号は混ぜない事
        strings = 'abcdefghijklmnopqrstuvwxyz' \
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZ' \
                    '0123456789'

        self.state = ''.join([random.choice(strings) for _ in range(12)])

        self.query_pool = {
            'response_type': 'code',
            'client_id': self.client_id,
            'client_secret': self.client_sec,
            'redirect_uri': f'http://localhost:{str(rcv_port)}',
            'scope': self.scope,
            'state': self.state,
            'grant_type': 'authorization_code',
        }

    # クエリプールから必要な分を取り出す、存在しないキーを指定しても無視されるが適切なエラーを返却するよう改良する？
    def _query_generator(self, *req_args, **optional):
        print(self.query_pool)
        gen_query = {_: self.query_pool[_] for _ in req_args}
        if optional != {}:
            for k, v in optional.items():
                gen_query.setdefault(k, v)
        return urlencode(gen_query)

    def get_token(self):

        httpd = WithTokenHTTPServer(('', self.rcv_port), TokenHandler)
        code_query = self._query_generator('response_type', 'client_id', 'redirect_uri', 'scope', 'state')
        print(code_query)

        # HACK:サーバプロセスをサブプロセスで動作させるように書き換える
        with futures.ThreadPoolExecutor(max_workers=2) as executor:

            # サーバ起動してリクエストを受け付ける状態へ
            executor.submit(httpd.serve_forever)

            # ブラウザ起動、認証画面を開く
            executor.submit(
                wb.open,
                f'{self.auth_url}?{code_query}',
                new=2,
                autoraise=True,
            )

            count = 0
            token_query = None
            while True :
                if httpd.redirect_query is not None:
                    print(f'code receive:{httpd.redirect_query}')
                    response_data = httpd.redirect_query
                    token_query = self._query_generator(
                        'client_id', 'client_secret', 'grant_type', 'redirect_uri',
                        code=response_data['code'][0],
                    )
                    break
                elif count == 10:
                    # サーバ停止コマンドが上手く処理されないので代替案を考える
                    print(f'server timeout, aborting processes...')
                    httpd.server_close()
                    return None
                time.sleep(1)
                count += 1
                print('receiving data...')

        #認証用URLが複数ある場合メソッドに持たせるかコンストラクタに持たせるか考える
        result_data, result_status = self._http_requester(
                'https://id.twitch.tv/oauth2/token',
                'POST',
                token_query,
            )

        if result_status == 200:
            return result_data
        else:
            print(f'トークン取得失敗\nステータス:{result_status}')
            return None


    def _http_requester(self, baseuri, methods, query):

            # 証明書設定
            http = ul3.PoolManager(
                cert_reqs='CERT_REQUIRED',
                ca_certs=certifi.where(),
            )

            response = http.request(
                methods,
                f'{baseuri}?{query}',
                headers= {'Content-Type': 'application/json'},
            )

            return json.loads(response.data.decode()), response.status





