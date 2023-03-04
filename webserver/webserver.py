#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Monster Hunter 3 Server Project web server.

    Monster Hunter 3 Server Project
    Copyright (C) 2023  Ze SpyRo

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""


import os
from flask import Flask, request, Response, render_template, abort


CONTENT_PATH = os.path.dirname(os.path.abspath(__file__))
VALID_CHARACTERS = [(' ','space'), ('A','A'), ('B','B'), ('C','C'), ('D','D'), ('E','E'),
                ('F','F'), ('G','G'), ('H','H'), ('I','I'), ('J','J'), ('K','K'),
                ('L','L'), ('M','M'), ('N','N'), ('O','O'), ('P','P'),
                ('Q','Q'), ('R','R'), ('S','S'), ('T','T'), ('U','U'), ('V','V'),
                ('W','W'), ('X','X'), ('Y','Y'), ('Z','Z'), ('a','_a'), ('b','_b'),
                ('c','_c'), ('d','_d'), ('e','_e'), ('f','_f'), ('g','_g'),
                ('h','_h'), ('i','_i'), ('j','_j'), ('k','_k'), ('l','_l'),
                ('m','_m'), ('n','_n'), ('o','_o'), ('p','_p'), ('q','_q'),
                ('r','_r'), ('s','_s'), ('t','_t'), ('u','_u'), ('v','_v'),
                ('w','_w'), ('x','_x'), ('y','_y'), ('z','_z'), ('0','0'),
                ('1','1'), ('2','2'), ('3','3'), ('4','4'),('5','5'), ('6','6'),
                ('7','7'), ('8','8'), ('9','9'),('0','0'), ('-', 'dash'), ('!','exclamationpoint'),
                ('?','questionmark'), ('(','leftparen'), (')','rightparen'), ('.','period'),
                (',','comma'), (':','colon'), (';','semicolon'), ('\'', 'apos'),
                ('"','quotes'), ('%','percent'), ('/', 'forwardslash')]


class EndpointResponse(object):
    def __init__(self, action, status, headers):
        self.action = action
        self.status = status
        self.headers = headers

    def __call__(self, **kwargs):
        return Response(self.action(**kwargs), status=self.status, headers=self.headers)


class WebServer:
    def __init__(self, hostname, port, name='MH3SP Webserver'):
        self.hostname = hostname
        self.port = port
        self.app = Flask(name, template_folder=CONTENT_PATH+"/templates", static_folder=CONTENT_PATH+"/static")
        self.app.before_request(self.verify_https)

    def get_servers(self):
        return [{'id':1, 'title':'Valor 1', 'description':'North America-based', 'population':201, 'capacity':2000},
                {'id':2, 'title':'Valor 2', 'description':'North America-based', 'population':76, 'capacity':2000},
                {'id':3, 'title':'Valor 3', 'description':'Europe-based', 'population':9, 'capacity':2000}]

    def get_server(self, server_id):
        for server in self.get_servers():
            if server['id'] == server_id:
                return server
        abort(404)

    def get_gates(self, server_id):
        return [{'id':i, 'title':'Gate '+str(i), 'population': (20-i)*3, 'capacity':100} for i in range(20)]

    def generate_letters(self, s="Hello World"):
        r = []
        for i in s:
            done=False
            for c, filename in VALID_CHARACTERS:
                if i == c:
                    done=True
                    r.append('/img/font/'+filename+'.bmp')
                    break
            if not done:
                r.append('')
        return r

    def generate_letterbox(self, string, height):
        res = "<ul class=\"d-flex justify-content-center flex-nowrap letterbox\">\n"
        for letter in string:
            res += "<img src=\""+ 'static'+(self.generate_letters(letter)[0] if self.generate_letters(letter)[0] else '') +"\""+ (("height="+str(height)) if self.generate_letters(letter)[0][-9:]!='space.bmp' else ("height=0 width="+str(int(height*5/8))))+" />\n"
        res += "</ul>"
        return res

    def index(self):
        with self.app.app_context(), self.app.test_request_context():
            return render_template('index.html', servers=self.get_servers(), generator=self.generate_letterbox)

    def server(self, server_id):
        with self.app.app_context(), self.app.test_request_context():
            return render_template('server.html', server=self.get_server(server_id), gates=self.get_gates(server_id), generator=self.generate_letterbox)

    def add_endpoint(self, endpoint=None, endpoint_name=None, handler=None):
        self.app.add_url_rule(endpoint, endpoint_name, EndpointResponse(handler, status=200, headers={}))

    def verify_https(self):
        if not request.is_secure:
            url = request.url.replace("http://", "https://", 1)
            return redirect(url, 301)

    def run(self):
        self.add_endpoint(endpoint='/', endpoint_name='index', handler=self.index)
        self.add_endpoint(endpoint='/<int:server_id>', endpoint_name='server', handler=self.server)
        self.app.run(debug=False, host=self.hostname, port=self.port, ssl_context=(CONTENT_PATH+'/cert.pem', CONTENT_PATH+'/key.pem'))
