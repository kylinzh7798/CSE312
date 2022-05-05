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
                print("here")
                header = 'HTTP/1.1 301 Moved Permanently\r\nX-Content-Type-Options: nosniff\r\nLocation:cheshire.cse.buffalo.edu:7798/\r\n\r\n'
                dataToSend = header.encode()
                print()
                self.request.sendall(dataToSend)


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

            header = header + "Content-length: "

            header = header + str(size+len(template.encode('utf-8'))+3)
            header = header + "\r\n\r\n"
            header_byte = str.encode(header)



            new_token = binascii.hexlify(os.urandom(11)).decode()
            lines = lines.replace("cse312profJesseHarloff", new_token)

            if xsrf_token != "":
                lines = lines. replace("WebSocketDefaultToken",xsrf_token)



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
                'HTTP/1.1 301 Moved Permanently\r\nContent-length: 13\r\nX-Content-Type-Options: nosniff\r\nLocation:http://localhost:7798/hello\r\n\r\n'.encode())

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



            username = "me"


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

        return template

    def escape_html(self, input):
        return input.replace(b'&', b'&amp').replace(b'<', b'&lt;').replace(b'>', b'&gt;')


if __name__ == '__main__':
    host = '0.0.0.0'
    port = 7798
    server = socketserver.ThreadingTCPServer((host, port), MyTCPHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)


