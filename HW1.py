import base64
import binascii
import hashlib
import json
import os
import socketserver
import sys
import bcrypt

import pymongo

from bson import json_util

client = pymongo.MongoClient()

class MyTCPHandler(socketserver.BaseRequestHandler):
    websocket_connections = []
    ws_users = {}

    def handle(self):

        full_data = self.request.recv(1024)
        while full_data.find(b"\r\n\r\n") == -1:
            full_data += self.request.recv(1024)
        if len(full_data) == 0: return

        client_id = self.client_address[0] + ':' + str(self.client_address[1])
        '''
        print('code------------------------------->')
        print(client_id + ' is sending data:')
        print(len(received_data))
        print(received_data.decode())
        print('decode Data String ------------------->'+received_data.decode())
        '''
        content = str(full_data.decode("utf-8")).split('/')

        sys.stdout.flush()
        sys.stderr.flush()
        print("content line: ____________________")
        print(content)
        print("---------------")
        if len(content) <= 1:
            return

        decode_data = full_data.decode("utf-8")
        start_pos = decode_data.find("Content-Length")

        # print("full data:", full_data)
        if content[0] == "POST " and content[1] == "image-upload HTTP":
            if start_pos > -1:

                start_pos += len("Content-Length: ")
                content_length = 0
                while True:
                    if decode_data[start_pos] == '\r':
                        break
                    content_length = content_length * 10 + int(decode_data[start_pos]) - int("0")
                    start_pos += 1

                self.request.settimeout(3)
                data = b""
                content_length -= (len(full_data) - full_data.find(b"\r\n\r\n"))+4

                while len(data) <= content_length:
                    data += self.request.recv(1024)


                full_data += data

            p = True
            token_text = "name=\"xsrf_token\"\r\n\r\n"
            token_text_byte = str.encode(token_text)
            token_code_start_pos = full_data.find(token_text_byte) + len(token_text_byte)
            token_code_end_pos = full_data[token_code_start_pos:].find(
                str.encode("\r\n")) + token_code_start_pos
            token_code_byte = full_data[token_code_start_pos:token_code_end_pos]
            token_code = token_code_byte.decode("utf-8")
            print("token", token_code)
            mydb = client["client"]
            token_list = mydb["token"]
            t = token_list.find_one({"token": token_code})
            if t is None:
                p = False
                print(token_code, " is not exist")

                self.request.sendall(
                    'HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-length: 13\r\n\r\nAccess denied'.encode())
            if p:
                boundary = "boundary="
                boundary_pos = full_data.find(str.encode(boundary))
                boundary_pos_start = boundary_pos + len(str.encode(boundary))
                for i in range(boundary_pos_start, len(full_data)):
                    if full_data[i:i + 1] == str.encode('-'):
                        boundary_pos_start += 1
                    else:
                        break
                boundary_pos_end = full_data[boundary_pos_start:].find(str.encode("\r\n")) + boundary_pos_start

                boundary_code = full_data[boundary_pos_start:boundary_pos_end].decode("utf-8")

                boundary_comment = boundary_code + "\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\n"
                boundary_comment_pos = full_data.find(str.encode(boundary_comment))

                ####
                boundary_file = boundary_code + "\r\nContent-Disposition: form-data; name=\"upload\""
                boundary_file_pos = full_data.find(str.encode(boundary_file))
                file_start_pos = full_data[boundary_file_pos:].find(str.encode("\r\n\r\n")) + 4 + boundary_file_pos
                last_boundary_pos = full_data[file_start_pos:].find(str.encode(boundary_code)) + file_start_pos
                file_end_pos = last_boundary_pos
                for i in range(last_boundary_pos - 1, 0, -1):
                    if full_data[i:i + 1] == str.encode('-'):
                        file_end_pos -= 1
                    else:
                        break
                file_end_pos -= 2

                file_bytes = b""
                if file_end_pos - file_start_pos > 1:
                    file_bytes = full_data[file_start_pos:file_end_pos]
                comment_start_pos = boundary_comment_pos + len(str.encode(boundary_comment))
                comment_end_pos = boundary_file_pos - 1
                for i in range(boundary_file_pos - 1, 0, -1):
                    if full_data[i:i + 1] == str.encode('-'):
                        comment_end_pos -= 1
                    else:
                        break
                comment_end_pos -= 1
                comment_length = comment_end_pos - comment_start_pos
                print(comment_length, comment_start_pos, comment_end_pos, full_data[comment_start_pos:comment_end_pos])
                comment = ""
                if comment_length > 0:
                    comment_byte = full_data[comment_start_pos:][:comment_length]
                    comment_byte = self.escape_html(comment_byte)
                    comment = comment_byte.decode("utf-8")

                mydb = client["client"]
                mycol = mydb["input"]
                filename_idx = mydb["idx"]
                document = filename_idx.find_one()
                id = 0
                if len(file_bytes) > 0:
                    if document is None:
                        filename_idx.insert_one({"idx": 0})
                    else:
                        id = document["idx"] + 1
                        new_query = {"$set": {"idx": id}}
                        filename_idx.update_one(document, new_query)
                    filename = "image/upload" + str(id) + ".jpg"

                    mycol.insert_one({"comment": comment, "image": file_bytes, "filename": filename})
                    print("filename: ", filename, "is created")

                    with open(filename, 'wb') as f:
                        f.write(file_bytes)

                else:
                    mycol.insert_one({"comment": comment, "image": file_bytes, "filename": "no file"})

                header = 'HTTP/1.1 301 Moved Permanently\r\nX-Content-Type-Options: nosniff\r\nLocation:http://localhost:8080/\r\n\r\n'
                dataToSend = header.encode()
                print()
                self.request.sendall(dataToSend)

        elif content[0] == "POST " and content[1] == "users HTTP":

            js = full_data.decode("utf-8").partition("\r\n\r\n")[2]
            dic = json.loads(js)
            email = dic['email']
            name = dic['username']
            next_id = 0

            mydb = client["student"]
            mycol = mydb['Next_ID']

            id_incr = mycol.find_one()
            if id_incr is None:
                next_id = 1
                mycol.insert_one({"_id": 1, "id": 1})

            else:
                _id = id_incr["id"]
                next_id = _id + 1
                new_query = {"$set": {"id": next_id}}
                mycol.update_one(id_incr, new_query)

            student_collection = mydb["student_col"]
            student_collection.insert_one({"id": next_id, "email": email, "username": name})

            header = "HTTP/1.1 201 Created\r\nContent-Type:application/json; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n"
            header = header + "Content-length: "
            body = json.dumps({"id": next_id, "email": email, "username": name})
            header = header + str(len(body))
            header = header + "\r\n\r\n"
            header = header + body
            dataToSend = header.encode()
            self.request.sendall(dataToSend)

        elif content[0] == "GET " and content[1] == "users HTTP":
            my_db = client["student"]
            my_col = my_db["student_col"]
            body = []
            for document in my_col.find({}, {"_id": 0, "id": 1, "email": 1, "username": 1}):
                body.append(document)

            header = "HTTP/1.1 200 OK\r\nContent-Type:application/json; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n"
            header = header + "Content-length: "
            js_body = json.dumps(body)
            header = header + str(len(js_body))
            header = header + "\r\n\r\n"
            header = header + js_body
            dataToSend = header.encode()
            self.request.sendall(dataToSend)

        elif content[0] == "GET " and content[1] == "users":

            str_id = content[2].split(' ')[0]
            int_id = 0
            for c in str_id:
                int_id = int_id * 10 + int(c) - int('0')
            my_db = client["student"]
            my_col = my_db["student_col"]
            data = my_col.find_one({"id": int_id}, {"_id": 0, "id": 1, "email": 1, "username": 1})

            if data is None:
                self.request.sendall(
                    'HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-length: 36\r\n\r\nThe '
                    'requested content does not exist'.encode())

            header = "HTTP/1.1 200 OK\r\nContent-Type:application/json; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n"
            header = header + "Content-length: "
            print(data)
            js_body = json_util.dumps(data)
            header = header + str(len(js_body))
            header = header + "\r\n\r\n"
            header = header + js_body
            dataToSend = header.encode()
            self.request.sendall(dataToSend)

        elif content[0] == "PUT " and content[1] == "users":

            str_id = content[2].split(' ')[0]
            int_id = 0
            for c in str_id:
                int_id = int_id * 10 + int(c) - int('0')
            my_db = client["student"]
            my_col = my_db["student_col"]
            data = my_col.find_one({"id": int_id})
            if data is None:
                self.request.sendall(
                    'HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-length: 36\r\n\r\nThe '
                    'requested content does not exist'.encode())

            js = full_data.decode("utf-8").partition("\r\n\r\n")[2]
            dic = json.loads(js)
            email = dic['email']
            name = dic['username']
            my_col.update_one({"id": int_id}, {"$set": {"email": email, "username": name}})

            header = "HTTP/1.1 201 Created\r\nContent-Type:application/json; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n"
            header = header + "Content-length: "
            body = json.dumps({"id": int_id, "email": email, "username": name})
            header = header + str(len(body))
            header = header + "\r\n\r\n"
            header = header + body
            dataToSend = header.encode()
            self.request.sendall(dataToSend)

        elif content[0] == "DELETE " and content[1] == "users":
            str_id = content[2].split(' ')[0]
            int_id = 0
            for c in str_id:
                int_id = int_id * 10 + int(c) - int('0')
            my_db = client["student"]
            my_col = my_db["student_col"]
            data = my_col.find_one({"id": int_id})
            if data is None:
                self.request.sendall(
                    'HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-length: 36\r\n\r\nThe '
                    'requested content does not exist'.encode())
            my_col.delete_one({"id": int_id})
            self.request.sendall(
                'HTTP/1.1 204 No Content\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-length: 0\r\n\r\n'.encode())

        elif content[0] == "POST " and content[1] == " HTTP":

            start_pos = full_data.find(b"Content-Length: ") + len(b"Content-Length: ")
            content_length = 0
            while True:
                if decode_data[start_pos] == '\r':
                    break
                content_length = content_length * 10 + int(decode_data[start_pos]) - int("0")
                start_pos += 1

            self.request.settimeout(3)
            data = b""
            content_length -= (len(full_data) - full_data.find(b"\r\n\r\n"))+4
            while len(data) <= content_length:
                data += self.request.recv(1024)

            full_data += data

            boundaryCode_start_pos = full_data.find(b"boundary=")+len(b"boundary=")
            boundaryCode_end_pos = full_data[boundaryCode_start_pos:].find(b"\r\n")+boundaryCode_start_pos
            boundaryCode = full_data[boundaryCode_start_pos:boundaryCode_end_pos]

            username_start_pos = full_data.find(boundaryCode+b"\r\n"+b'Content-Disposition: form-data; name="Name"\r\n\r\n')+len(boundaryCode+b"\r\n"+b'Content-Disposition: form-data; name="Name"\r\n\r\n')
            username_end_pos = full_data[username_start_pos:].find(b"\r\n--"+boundaryCode)+username_start_pos
            username = full_data[username_start_pos:username_end_pos]
            username = self.escape_html(username)

            password_start_pos = full_data.find(boundaryCode+b"\r\n"+b'Content-Disposition: form-data; name="Password"\r\n\r\n')+len(boundaryCode+b"\r\n"+b'Content-Disposition: form-data; name="Password"\r\n\r\n')
            password_end_pos = full_data[password_start_pos:].find(b"\r\n--"+boundaryCode)+password_start_pos
            password = full_data[password_start_pos:password_end_pos]
            hashed = bcrypt.hashpw(password, bcrypt.gensalt())

            AuthenticationDB = client['AuthenticationDB']
            userInfor = AuthenticationDB['userInfor']

            visited = self.get_visited(full_data)
            # login in
            if full_data.find(boundaryCode+b"\r\n"+b'Content-Disposition: form-data; name="registration"\r\n\r\n') == -1:

                result = userInfor.find_one({"username": username})

                if result is None:
                    f = open('index.html', 'rb')
                    lines = b""
                    for line in f:
                        lines += line
                    lines = lines.replace(b"NumberOfVisited",str(visited).encode())
                    lines = lines.replace(b"{{message display}}",b"<h1>Username is not exist,login in failed</h1>")
                    template = self.get_comment_history().encode()
                    size = len(lines)+len(template)

                    header = b"HTTP/1.1 200 OK\r\nSet-Cookie: visited="+str(visited).encode()+b"; Max-Age=3600\r\nContent-Type: text/html; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-length: "+str(size).encode()+b"\r\n\r\n"+lines+template
                    self.request.sendall(header)
                elif not bcrypt.checkpw(password, result['password']):

                    f = open('index.html', 'rb')
                    lines = b""
                    for line in f:
                        lines += line
                    lines = lines.replace(b"NumberOfVisited",str(visited).encode())
                    lines = lines.replace(b"{{message display}}",b"<h1>Username and Password does not match,login in failed</h1>")
                    template = self.get_comment_history().encode()
                    size = len(lines)+len(template)
                    header = b"HTTP/1.1 200 OK\r\nSet-Cookie: visited="+str(visited).encode()+b"; Max-Age=3600\r\nContent-Type: text/html; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-length: "+str(size).encode()+b"\r\n\r\n"+lines+template
                    self.request.sendall(header)
                else:
                    f = open('index.html', 'rb')
                    lines = b""
                    for line in f:
                        lines += line
                    ws_xsrf_token = result['ws_xsrf_token']
                    lines = lines.replace(b"WebSocketDefaultToken",ws_xsrf_token.encode())
                    lines = lines.replace(b"NumberOfVisited",str(visited).encode())
                    lines = lines.replace(b"{{message display}}",b"<h1>Welcome back, "+result['username']+b"!</h1>")
                    template = self.get_comment_history().encode()
                    size = len(lines)+len(template)
                    authentication_token = binascii.hexlify(os.urandom(11))
                    authentication_token_secure = bcrypt.hashpw(authentication_token, bcrypt.gensalt())
                    print("find:", userInfor.find_one({"username":username}))

                    userInfor.update_one({"username":username},{'$set':{"authentication_token":authentication_token_secure}})

                    header = b"HTTP/1.1 200 OK\r\nSet-Cookie: visited="+str(visited).encode()+b"; Max-Age=3600\r\nSet-Cookie: authentication_token="+authentication_token+b"; Max-Age=3600; HttpOnly\r\n"+b"Content-Type: text/html; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-length: "+str(size).encode()+b"\r\n\r\n"+lines+template
                    self.request.sendall(header)
            # registration
            else:
                result = userInfor.find_one({"username":username})
                if result is None:
                    xsrf_token = binascii.hexlify(os.urandom(11)).decode()
                    authentication_token = bcrypt.hashpw(binascii.hexlify(os.urandom(11)),bcrypt.gensalt())
                    userInfor.insert_one({"username": username, "password": hashed, "authentication_token": authentication_token, "ws_xsrf_token": xsrf_token})
                    f = open('index.html', 'rb')
                    lines = b""
                    for line in f:
                        lines += line
                    lines = lines.replace(b"NumberOfVisited",str(visited).encode())
                    lines = lines.replace(b"{{message display}}",b"<h1>Successful registration, you may log in!</h1>")
                    template = self.get_comment_history().encode()
                    size = len(lines)+len(template)
                    header = b"HTTP/1.1 200 OK\r\nSet-Cookie: visited="+str(visited).encode()+b"; Max-Age=3600\r\nContent-Type: text/html; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-length: "+str(size).encode()+b"\r\n\r\n"+lines+template
                    self.request.sendall(header)

                else:
                    f = open('index.html', 'rb')
                    lines = b""
                    for line in f:
                        lines += line
                    lines = lines.replace(b"NumberOfVisited",str(visited).encode())
                    lines = lines.replace(b"{{message display}}",b"<h1>Username already exist, pick a different name!</h1>")
                    template = self.get_comment_history().encode()
                    size = len(lines)+len(template)
                    header = b"HTTP/1.1 200 OK\r\nSet-Cookie: visited="+str(visited).encode()+b"; Max-Age=3600\r\nContent-Type: text/html; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-length: "+str(size).encode()+b"\r\n\r\n"+lines+template
                    self.request.sendall(header)

        elif content[0] == "GET " and content[1] == " HTTP":
            username = ""
            xsrf_token = ""
            # has authentication token
            if full_data.find(b"authentication_token") != -1:

                token_start_pos = full_data.find(b"authentication_token=")+len(b"authentication_token=")
                token_end_pos = token_start_pos
                for i in range(token_start_pos,len(full_data)):
                    if full_data[i:i+1] == b';' or full_data[i:i+1] == b"\r":
                        break
                    else:
                        token_end_pos += 1
                token = full_data[token_start_pos:token_end_pos]
                print("cookie token： ",token)
                AuthenticationDB = client['AuthenticationDB']
                userInfor = AuthenticationDB['userInfor']

                for item in userInfor.find():
                    print("item: ",item)
                    if bcrypt.checkpw(token,item['authentication_token']):
                        username = item['username'].decode()
                        xsrf_token = item['ws_xsrf_token']
            print("username:", username)
            template = self.get_comment_history()
            visited = self.get_visited(full_data)
            header = "HTTP/1.1 200 OK\r\nSet-Cookie: visited="+str(visited)+"; Max-Age=3600\r\nContent-Type: text/html; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n"

            f = open('index.html', 'r')
            # size = os.path.getsize("index.html")

            lines = ""
            for line in f:
                lines += line
            lines = lines.replace("NumberOfVisited",str(visited))
            if username == "":
                lines = lines.replace("{{message display}}", "")
            else:
                lines = lines.replace("{{message display}}", "<h1>Welcome back, "+username+"!</h1>")


            size = len(lines)
            mydb = client["client"]
            token_list = mydb["token"]
            header = header + "Content-length: "

            header = header + str(size+len(template.encode('utf-8'))+3)
            header = header + "\r\n\r\n"
            header_byte = str.encode(header)

            if token_list.find_one() is None:
                print("first time")
                token_list.insert_one({"token": "cse312profJesseHarloff"})

            new_token = binascii.hexlify(os.urandom(11)).decode()
            lines = lines.replace("cse312profJesseHarloff", new_token)

            if xsrf_token != "":
                lines = lines. replace("WebSocketDefaultToken",xsrf_token)

            token_list.insert_one({"token": new_token})

            header_byte += str.encode(lines)
            header_byte += template.encode("utf-8")
            self.request.sendall(header_byte)

        elif content[1] == "style.css HTTP":
            header = "HTTP/1.1 200 OK\r\nContent-Type: text/css; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n"
            f = open('style.css', 'r')
            size = os.path.getsize("style.css")
            header = header + "Content-length: "
            header = header + str(size)
            header = header + "\r\n\r\n"
            for line in f:
                header = header + line
            dataToSend = header.encode()
            self.request.sendall(dataToSend)
        elif content[1] == "functions.js HTTP":

            header = "HTTP/1.1 200 OK\r\nContent-Type: text/javascript; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n"
            f = open('functions.js', 'r')

            size = os.path.getsize("functions.js")
            header = header + "Content-length: "
            header = header + str(size)
            header = header + "\r\n\r\n"
            for line in f:
                header = header + line
            dataToSend = header.encode()


            self.request.sendall(dataToSend)
        elif content[1] == "image" and content[2] == "flamingo.jpg HTTP":
            header = bytes(
                "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n",
                encoding='utf8')
            f = open('image/flamingo.jpg', 'rb')
            size = os.path.getsize("image/flamingo.jpg")
            header = header + bytes("Content-length: ", encoding='utf8')
            header = header + bytes(str(size), encoding='utf8')
            header = header + bytes("\r\n\r\n", encoding='utf8')
            for line in f:
                header = header + line
            self.request.sendall(header)
        elif content[1] == "image" and content[2] == "cat.jpg HTTP":
            header = bytes(
                "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n",
                encoding='utf8')
            f = open('image/cat.jpg', 'rb')
            size = os.path.getsize("image/cat.jpg")
            header = header + bytes("Content-length: ", encoding='utf8')
            header = header + bytes(str(size), encoding='utf8')
            header = header + bytes("\r\n\r\n", encoding='utf8')
            print(len(header))
            for line in f:
                header = header + line
            self.request.sendall(header)
        elif content[1] == "image" and content[2] == "dog.jpg HTTP":
            header = bytes(
                "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n",
                encoding='utf8')

            f = open('image/dog.jpg', 'rb')
            size = os.path.getsize("image/dog.jpg")
            header = header + bytes("Content-length: ", encoding='utf8')
            header = header + bytes(str(size), encoding='utf8')

            for line in f:
                header = header + line

            header = header + bytes("\r\n\r\n", encoding='utf8')
            self.request.sendall(header)
        elif content[1] == "image" and content[2] == "eagle.jpg HTTP":
            header = bytes(
                "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n",
                encoding='utf8')
            f = open('image/eagle.jpg', 'rb')
            size = os.path.getsize("image/eagle.jpg")
            header = header + bytes("Content-length: ", encoding='utf8')
            header = header + bytes(str(size), encoding='utf8')
            header = header + bytes("\r\n\r\n", encoding='utf8')
            print(len(header))
            for line in f:
                header = header + line
            self.request.sendall(header)
        elif content[1] == "image" and content[2] == "elephant.jpg HTTP":
            header = bytes(
                "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n",
                encoding='utf8')
            f = open('image/elephant.jpg', 'rb')
            size = os.path.getsize("image/elephant.jpg")
            header = header + bytes("Content-length: ", encoding='utf8')
            header = header + bytes(str(size), encoding='utf8')
            header = header + bytes("\r\n\r\n", encoding='utf8')
            print(len(header))
            for line in f:
                header = header + line
            self.request.sendall(header)
        elif content[1] == "image" and content[2] == "kitten.jpg HTTP":
            header = bytes(
                "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n",
                encoding='utf8')
            f = open('image/kitten.jpg', 'rb')
            size = os.path.getsize("image/kitten.jpg")
            header = header + bytes("Content-length: ", encoding='utf8')
            header = header + bytes(str(size), encoding='utf8')
            header = header + bytes("\r\n\r\n", encoding='utf8')
            print(len(header))
            for line in f:
                header = header + line
            self.request.sendall(header)
        elif content[1] == "image" and content[2] == "parrot.jpg HTTP":
            header = bytes(
                "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n",
                encoding='utf8')
            f = open('image/parrot.jpg', 'rb')
            size = os.path.getsize("image/parrot.jpg")
            header = header + bytes("Content-length: ", encoding='utf8')
            header = header + bytes(str(size), encoding='utf8')
            header = header + bytes("\r\n\r\n", encoding='utf8')
            print(len(header))
            for line in f:
                header = header + line
            self.request.sendall(header)
        elif content[1] == "image" and content[2] == "rabbit.jpg HTTP":
            header = bytes(
                "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n",
                encoding='utf8')
            f = open('image/rabbit.jpg', 'rb')
            size = os.path.getsize("image/rabbit.jpg")
            header = header + bytes("Content-length: ", encoding='utf8')
            header = header + bytes(str(size), encoding='utf8')
            header = header + bytes("\r\n\r\n", encoding='utf8')
            for line in f:
                header = header + line
            self.request.sendall(header)
        elif content[1] == "image":
            print(content)
            print(content[2])
            if ".." in content:
                self.request.sendall(
                    'HTTP/1.1 404    Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-length: 36\r\n\r\nThe '
                    'requested content does not exist'.encode())
            filename = 'image/' + content[2][:content[2].find(".jpg")] + ".jpg"
            header = bytes(
                "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n",
                encoding='utf8')

            f = open(filename, 'rb')

            size = os.path.getsize(filename)
            header = header + bytes("Content-length: ", encoding='utf8')
            header = header + bytes(str(size), encoding='utf8')
            header = header + bytes("\r\n\r\n", encoding='utf8')
            for line in f:
                header = header + line
            self.request.sendall(header)
        elif content[1] == "hello HTTP":
            self.request.sendall(
                'HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-length: 12\r\n\r\nHello World!'.encode())
        elif content[1] == "hi HTTP":

            self.request.sendall(
                'HTTP/1.1 301 Moved Permanently\r\nContent-length: 13\r\nX-Content-Type-Options: nosniff\r\nLocation:http://localhost:8080/hello\r\n\r\n'.encode())
        elif content[0] =='GET ' and content[1] == 'chat-history HTTP':
            header = "HTTP/1.1 200 OK\r\nContent-Type:application/json;charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n"
            hw3db = client["hw3db"]
            chat_history = hw3db["chat_history"]
            chats = []
            for document in chat_history.find():
                chats.append({'username':document['username'],'comment':document['comment']})
            json_chat = json.dumps(chats,default=str)
            header += "Content-length: "+str(len(json_chat)) + '\r\n\r\n'+json_chat

            self.request.sendall(header.encode())
        elif content[0] == 'GET ' and content[1] == "websocket HTTP":
            # check authentication_token is valid
            token_start_pos = full_data.find(b"authentication_token=")+len(b"authentication_token=")
            token_end_pos = token_start_pos
            for i in range(token_start_pos,len(full_data)):
                if full_data[i:i+1] == b';' or full_data[i:i+1] == b"\r":
                    token_end_pos = i
                    break
            token = full_data[token_start_pos:token_end_pos]
            print(token)

            AuthenticationDB = client['AuthenticationDB']
            userInfor = AuthenticationDB['userInfor']

            username = ""
            for item in userInfor.find():
                if bcrypt.checkpw(token,item["authentication_token"]):
                    username = item["username"].decode()

            if username == "":
                print("403 response")
                return
            #     self.request.sendall(
            #         'HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-length: 36\r\n\r\nAccess denied, Invalid WS xsrf token'.encode())
            else:
                # pass check, begin to establish the 101 connection
                header = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: "
                start_pos = decode_data.find("Sec-WebSocket-Key: ") + len("Sec-WebSocket-Key: ")
                end_pos = start_pos
                guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                for i in range(start_pos, len(decode_data)):
                    if decode_data[i] == '\r':
                        break
                    else:
                        end_pos += 1
                key = decode_data[start_pos:end_pos]

                toHash = key + guid
                hash_key = hashlib.sha1(toHash.encode())
                hash_byte = hash_key.digest()
                base64_byte = base64.b64encode(hash_byte)
                header_byte = header.encode()
                header_byte += base64_byte + str.encode("\r\n\r\n")
                self.request.sendall(header_byte)

                # validate the authentication cookie
                if username != "":
                    MyTCPHandler.websocket_connections.append(self)
                    MyTCPHandler.ws_users[username] = self

                    while True:

                        recv_bytes = self.request.recv(1024)

                        if len(recv_bytes) > 6:
                            print("bug")
                            if recv_bytes[0] == 1:
                                print("recv header 00000001 11111110,  this is invalid")

                            if recv_bytes[0] == 136:
                                print(recv_bytes)
                                print(username," is disconnected ___________________________")
                                MyTCPHandler.websocket_connections.remove(MyTCPHandler.ws_users[username])
                                MyTCPHandler.ws_users.pop(username)
                                print("remaining client in the server: ",MyTCPHandler.ws_users.keys())
                                break
                            payload_len = recv_bytes[1]

                            if payload_len>127:
                                payload_len -= 128
                            else:
                                print(recv_bytes[1])
                                print(recv_bytes)
                                print("msg mask bit is 0 ########################")

                            if payload_len == 127:
                                actual_len = recv_bytes[9] + recv_bytes[8]*256 + recv_bytes[7] *65536+recv_bytes[6]*16777216 +recv_bytes[5]*4294967296+recv_bytes[4]
                                if actual_len > 1024:
                                    # buffering data if we have byte not read yet
                                    while(len(recv_bytes)-8 < actual_len):
                                        recv_bytes += self.request.recv(1024)
                                    print("127 done buffering")
                                start_pos = 112

                            elif payload_len == 126:
                                print("126 recv bytes: ",recv_bytes[0:10])
                                actual_len = recv_bytes[2]*256+recv_bytes[3]
                                if actual_len > 1016:
                                    # buffering data if we have byte not read yet
                                    while(len(recv_bytes)-8 < actual_len):
                                        print("126:buffering")
                                        recv_bytes += self.request.recv(1024)
                                start_pos = 64

                            else:
                                actual_len = payload_len
                                start_pos = 48

                            recv_bin = ""
                            for b in recv_bytes:
                                recv_bin += '{0:08b}'.format(b)
                            mask = recv_bin[start_pos-32:start_pos]
                            payload_bin = ""

                            # mask payload
                            for i in range(start_pos,len(recv_bin)):
                                payload_bin += str(int(recv_bin[i])^int(mask[(i-start_pos)%32]))
                            print("bin",payload_bin)
                            chat_msg_bin = ''.join(format(ord(i), '08b') for i in '{"messageType":"chatMessage"')
                            offer_bin = ''.join(format(ord(i), '08b') for i in '{"messageType":"webRTC-offer"')
                            answer_bin = ''.join(format(ord(i), '08b') for i in '{"messageType":"webRTC-answer"')
                            cand_bin = ''.join(format(ord(i), '08b') for i in '{"messageType":"webRTC-candidate"')
                            # print("payloadbin: ",payload_bin)
                            #
                            # print("offer_bin: ",offer_bin)
                            # print("find: ",payload_bin.find(offer_bin))
                            # print("answer_bin: ",answer_bin)
                            # print("find: ",payload_bin.find(answer_bin))
                            # print("cand_bin: ",cand_bin)
                            # print("find: ",payload_bin.find(cand_bin))

                            # if payload is webRTC
                            if payload_bin.find(offer_bin) == 0 or payload_bin.find(answer_bin) == 0 or payload_bin.find(cand_bin) == 0:
                                print("video chat")
                                if payload_len == 127:
                                    print("127")
                                    lengthToSend = '{0:064b}'.format(actual_len)
                                    frameToSend = "1000000101111111" + lengthToSend + payload_bin
                                    bytesToSend = int(frameToSend, 2).to_bytes((len(frameToSend) + 7) // 8, byteorder='big')
                                    bytesToSend = bytesToSend[:actual_len+10]
                                    for k,v in MyTCPHandler.ws_users.items():
                                        if k != username:
                                            print(username + " is sending to "+k)
                                            v.request.sendall(bytesToSend)
                                elif payload_len == 126:
                                    print("126")
                                    lengthToSend = '{0:016b}'.format(actual_len)
                                    frameToSend = "1000000101111110" + lengthToSend + payload_bin

                                    bytesToSend = int(frameToSend, 2).to_bytes((len(frameToSend) + 7) // 8, byteorder='big')
                                    bytesToSend = bytesToSend[:actual_len+4]
                                    print("actual_len: ",actual_len)
                                    print("frame: ",frameToSend[0:16],frameToSend[16:32],frameToSend[32:])
                                    print("number of conn: ",len(MyTCPHandler.websocket_connections))
                                    print("Who is in the connection: ",MyTCPHandler.ws_users.keys())
                                    for k,v in MyTCPHandler.ws_users.items():
                                        if k != username:
                                            print(username + " is sending to "+k)
                                            v.request.sendall(bytesToSend)

                                else:
                                    print("less than 126")
                                    lengthToSend = '{0:08b}'.format(actual_len)
                                    frameToSend = "10000001" + lengthToSend + payload_bin
                                    bytesToSend = int(frameToSend, 2).to_bytes((len(frameToSend) + 7) // 8, byteorder='big')
                                    bytesToSend = bytesToSend[:actual_len+2]
                                    for k,v in MyTCPHandler.ws_users.items():
                                        if k != username:
                                            print(username + " is sending to "+k)
                                            v.request.sendall(bytesToSend)
                            # if payload is chat message
                            elif payload_bin.find(chat_msg_bin) == 0:

                                print("len_payload: ",len(payload_bin))
                                payload_msg = json.loads(int(payload_bin, 2).to_bytes((len(payload_bin) + 7) // 8, byteorder='big').decode('utf-8'))
                                ws_xsrf_token = payload_msg['ws_xsrf_token']

                                ws_result = userInfor.find_one({"ws_xsrf_token":ws_xsrf_token})
                                # validate html token, if not valid, break immediately
                                if ws_result is None:
                                    break
                                else:
                                    payload_msg["username"] = username
                                    print('msg:',payload_msg)

                                    payload_msg["comment"] = self.escape_html(payload_msg["comment"].encode()).decode('utf-8')

                                    msg_bytes = json.dumps(payload_msg,default=str).encode()
                                    payloadToSend = ""
                                    for b in msg_bytes:
                                        payloadToSend += '{0:08b}'.format(b)
                                    new_data_len = len(json.dumps(payload_msg).encode())

                                    if new_data_len >= 65536:
                                        lengthToSend = '{0:064b}'.format(len(json.dumps(payload_msg).encode()))
                                        frameToSend = "1000000101111111" + lengthToSend + payloadToSend
                                        bytesToSend = int(frameToSend, 2).to_bytes((len(frameToSend) + 7) // 8, byteorder='big')

                                        for conn in MyTCPHandler.websocket_connections:
                                            conn.request.sendall(bytesToSend)

                                    elif new_data_len >= 126:
                                        lengthToSend = '{0:016b}'.format(len(json.dumps(payload_msg).encode()))
                                        frameToSend = "1000000101111110" + lengthToSend + payloadToSend
                                        bytesToSend = int(frameToSend, 2).to_bytes((len(frameToSend) + 7) // 8, byteorder='big')
                                        for conn in MyTCPHandler.websocket_connections:
                                            conn.request.sendall(bytesToSend)

                                    else:
                                        lengthToSend = '{0:08b}'.format(len(json.dumps(payload_msg).encode()))
                                        frameToSend = "10000001" + lengthToSend + payloadToSend
                                        bytesToSend = int(frameToSend, 2).to_bytes((len(frameToSend) + 7) // 8, byteorder='big')

                                        for conn in MyTCPHandler.websocket_connections:
                                            conn.request.sendall(bytesToSend)

                                    hw3db = client["hw3db"]
                                    chat_history = hw3db["chat_history"]
                                    payload_msg['len'] = len(str(payload_msg).encode())
                                    chat_history.insert_one(payload_msg)
                                    print("done")
                            else:
                                print("***recv: ",recv_bytes)
                                print("receive ws bytes that is not match to one in above")
        else:
            self.request.sendall(
                'HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-length: 36\r\n\r\nThe '
                'requested content does not exist'.encode())

    def newline(self, comment):
        comment_byte = str.encode(comment)
        new_line_tag = str.encode("<br>")
        new_comment_byte = comment_byte.replace(b'\r\n', new_line_tag).replace(b'\n', new_line_tag).replace(b'\r',
                                                                                                            new_line_tag)
        return new_comment_byte.decode("utf-8")

    def get_visited(self,full_data):
        if full_data.find(b"visited") == -1:
            visited = 1
        else:
            visited_start_pos = full_data.find(b"visited=")+len(b"visited=")
            visited = 0
            for i in range(visited_start_pos,len(full_data)):
                if full_data[i:i+1] == b'\r' or full_data[i:i+1] == b';':
                    break
                else:
                    visited = visited*10 + int(full_data[i:i+1].decode())
            visited += 1
        return visited

    def get_comment_history(self):
        template = ""
        mydb = client["client"]
        mycol = mydb["input"]
        for document in mycol.find():
            if document["comment"] != "" and document["image"] != b"":
                # print("has image")

                comment = self.newline(document["comment"])
                template = template + comment + "<br>"
                template = template + "<img src=" + '"' + document[
                    "filename"] + '" ' + " alt=\"Client's image\" class=\"my_image\"/>"
                template = template + "<br>"
            elif document["comment"] == "" and document["image"] != b"":
                # print("dont have image")
                template = template + "<img src=" + document[
                    "filename"] + " alt=\"Client's image\" class=\"my_image\"/>"
                template = template + "<br>"
            elif document["comment"] != "" and document["image"] == b"":
                comment = self.newline(document["comment"])
                template = template + comment + "<br>"
        return template

    def escape_html(self, input):
        return input.replace(b'&', b'&amp').replace(b'<', b'&lt;').replace(b'>', b'&gt;')


if __name__ == '__main__':
    host = '0.0.0.0'
    port = 7191

    server = socketserver.ThreadingTCPServer((host, port), MyTCPHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)


