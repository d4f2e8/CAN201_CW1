import argparse
import json
import math
import os
import struct
import threading
import time
from socket import *

from Crypto.Cipher import AES

key = '1823678008763281'
aes = AES.new(str.encode(key), AES.MODE_ECB)  # the key
encryption_on = "no"
block_size = 1024 * 1024 * 2
share_file_directory = "share"
port_list = [20003, 20004, 20005, 20006, 20007, 20008, 20009, 20010, 20011]  # limit the ports that can be used
ip_list = []
socket_for_peer = {}  # record the socket for peers
peer_status = {}  # record the peers' status
total_file = {}  # no matter how many files are in the directory, just treat as new added ones
new_add_file = {}  # local new added files
new_update_file = []  # local new updated files
new_file_from_peer = []  # new files received from peers
new_update_from_peer = []  # the new updated files received from peers
# for one peer
# number 1 for inform peer
main_port1 = 20001
main_socket1 = socket(AF_INET, SOCK_STREAM)
main_socket1.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
main_socket1.bind(('', main_port1))
main_socket1.listen(20)
# number 2 for transfer data
main_port2 = 20002
main_socket2 = socket(AF_INET, SOCK_STREAM)
main_socket2.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
main_socket2.bind(('', main_port2))
main_socket2.listen(20)


# local methods
def _argparse():
    parser = argparse.ArgumentParser(description="This is description!")
    parser.add_argument('--ip', action='store', required=True,
                        dest='ip', help='ip addresses of peers')
    parser.add_argument('--encryption', action='store', required=False,
                        dest='encryption', help='use encryption transmission')
    return parser.parse_args()


def input_values():
    global ip_list, encryption_on
    parser = _argparse()
    ip_list = parser.ip.split(",")
    for ip in ip_list:
        peer_status[ip] = 0
    if parser.encryption is not None:
        encryption_on = parser.encryption


def get_file_size(filename):
    return os.path.getsize(filename)


def get_file_block(filename, block_index):
    global block_size
    f = open(filename, 'rb')
    f.seek(block_index * block_size)
    file_block = f.read(block_size)
    f.close()
    return file_block


# complement the text using blank space so that the length of the text is 16*n
def encrypt_text(text):
    while len(text) % 16 != 0:
        text += b' '
    return aes.encrypt(text)


def decrypt_text(text):
    text = aes.decrypt(text)
    return text.rstrip(b' ')


def detect_change(ip_list):
    have_new_file = {}  # use it to decide whether to inform peers about the new added files
    have_update_file = {}  # use it to decide whether to inform peers about the new updated files
    for ip in ip_list:
        have_new_file[ip] = 0
        have_update_file[ip] = 0
    global total_file, new_add_file, new_update_file
    while True:
        total_file_after_detect = {}
        for root, dirs, files in os.walk(share_file_directory, followlinks=True):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    total_file_after_detect[file_path] = {"last_update_time": os.path.getmtime(file_path),
                                                          "file_size": get_file_size(file_path)}
                except:
                    total_file_after_detect[file_path] = {"last_update_time": total_file[file_path]["last_update_time"],
                                                          "file_size": total_file[file_path]["file_size"]}
        for file in total_file_after_detect:
            # total_file[file] == 1 means the file is being modified, the information about it makes no sense
            if file in total_file and total_file[file] == 1:
                total_file_after_detect[file] = 1
            # file is in total_file_after_update but not in total_file, it is a new added file
            if file not in total_file:
                new_add_file[file] = total_file_after_detect[file]
                total_file[file] = total_file_after_detect[file]
                for ip in ip_list:
                    have_new_file[ip] = 1
            if file in total_file and total_file[file] != 1:
                if total_file_after_detect[file]["last_update_time"] > total_file[file]["last_update_time"]:
                    total_file[file] = total_file_after_detect[file]
                    if file not in new_update_file:
                        new_update_file.append(file)
                        for ip in ip_list:
                            have_update_file[ip] = 1
        for ip in ip_list:
            if have_new_file[ip] == 1 and peer_status[ip] == 1:
                inform_new_file(socket_for_peer[ip][0])
                have_new_file[ip] = 0
            if have_update_file[ip] == 1 and peer_status[ip] == 1:
                inform_update_file(socket_for_peer[ip][0])
                have_update_file[ip] = 0
        new_update_file = []


# update the variables when receives information
# if the file is not in local file, it is a new file from the peer.
# If it is in local file but the size of the local file is smaller than the received one, need further transfer.
def update_new_file_from_peer(data, address):
    for file_name in data['new_add_file']:
        if file_name not in total_file:
            file = {'file_name': file_name, 'file_info': data["new_add_file"][file_name], "ip_address": address}
            if file not in new_file_from_peer:
                new_file_from_peer.append(file)
        if file_name in total_file and total_file[file_name] != 1 and get_file_size(file_name) < \
                data["new_add_file"][file_name]["file_size"]:
            further_transfer(socket_for_peer[address][1], file_name, data["new_add_file"][file_name]["file_size"])


# detect whether new_file_from_peer and new_update_from_peer are empty. If not, need to request these files
def detect_new_file_from_peer(ip_address):
    global new_file_from_peer, new_update_from_peer
    while True:
        new_file = {}
        if new_file_from_peer:
            for index_i, value in enumerate(new_file_from_peer):
                if value["ip_address"] == ip_address:
                    new_file = new_file_from_peer.pop(index_i)
                    break
            if new_file:
                for index_i, value in enumerate(new_file_from_peer):
                    if value["file_name"] == new_file["file_name"]:
                        new_file_from_peer.pop(index_i)
                        break
                request_new_file_from_peer(new_file, socket_for_peer[ip_address][1])
        if new_update_from_peer:
            new_file = {}
            for index_i, value in enumerate(new_update_from_peer):
                if value["ip_address"] == ip_address:
                    new_file = new_update_from_peer.pop(index_i)
            if new_file:
                request_update_from_peer(new_file["file_name"], socket_for_peer[ip_address][1])


# client methods
# say hello and tell other peers what i have.
def detect_peer(ip_address):
    try:
        socket_for_peer[ip_address][0].connect((ip_address, main_port1))
        socket_for_peer[ip_address][1].connect((ip_address, main_port2))
    except:
        peer_status[ip_address] = 0
        print(ip_address, "offline")
    else:
        peer_status[ip_address] = 1
        print(ip_address, "online")
        if new_add_file:
            data = {"operation_code": 0, "server_operation_code": 1, "new_add_file": new_add_file}
            format_data = json.dumps(data).encode()
            if encryption_on == "yes":
                format_data = encrypt_text(format_data)
            encode_data = struct.pack('!I', len(format_data)) + format_data
            socket_for_peer[ip_address][0].send(encode_data)
        else:
            data = {"operation_code": 0, "server_operation_code": 0}
            format_data = json.dumps(data).encode()
            if encryption_on == "yes":
                format_data = encrypt_text(format_data)
            encode_data = struct.pack('!I', len(format_data)) + format_data
            socket_for_peer[ip_address][0].send(encode_data)
        msg = socket_for_peer[ip_address][0].recv(4)
        length = struct.unpack('!I', msg)[0]
        msg = socket_for_peer[ip_address][0].recv(length)
        if encryption_on == "yes":
            msg = decrypt_text(msg)
        unformatted_data = json.loads(msg.decode())
        if unformatted_data["server_operation_code"] == 1:
            update_new_file_from_peer(unformatted_data, ip_address)


# inform other peers that i have new file
def inform_new_file(socket):
    data = {"operation_code": 1, "new_add_file": new_add_file}
    format_data = json.dumps(data).encode()
    if encryption_on == "yes":
        format_data = encrypt_text(format_data)
    encode_data = struct.pack('!I', len(format_data)) + format_data
    socket.send(encode_data)


# inform other peers that some file of mine is updated
def inform_update_file(socket):
    data = {"operation_code": 2, "new_update_file": new_update_file}
    format_data = json.dumps(data).encode()
    if encryption_on == "yes":
        format_data = encrypt_text(format_data)
    encode_data = struct.pack('!I', len(format_data)) + format_data
    socket.send(encode_data)


# start to request new file from peer
def request_new_file_from_peer(file, socket):
    time_start = time.time()
    print("start request")
    operation_code = 3
    file_name = file["file_name"]
    total_file[file_name] = 1
    total_file_size = file["file_info"]["file_size"]
    file_path = os.path.split(file_name)
    if not os.path.exists(file_path[0]):
        os.mkdir(file_path[0])
    rest_file_size = total_file_size
    total_block_number = math.ceil(total_file_size / block_size)
    print(total_block_number)
    f = open(file_name, 'wb')
    block_index = 0
    while rest_file_size > 0:
        if block_index <= total_block_number:
            header = struct.pack('!II', operation_code, block_index)
            format_data = header + file_name.encode()
            if encryption_on == "yes":
                format_data = encrypt_text(format_data)
            header_length = len(format_data)
            binary_data = struct.pack('!I', header_length) + format_data
            socket.send(binary_data)
        if encryption_on == "no":
            msg = socket.recv(block_size * 3)
            f.write(msg)
            receive_data_size = len(msg)
            rest_file_size = rest_file_size - receive_data_size
            block_index += 1
        else:
            if rest_file_size >= block_size:
                rest_for_one_time = block_size
            else:
                rest_for_one_time = math.ceil(rest_file_size / 16) * 16
            text = b''
            while rest_for_one_time > 0:
                msg = socket.recv(rest_for_one_time)
                text += msg
                receive_data_size = len(msg)
                rest_for_one_time = rest_for_one_time - receive_data_size
            text = decrypt_text(text)
            f.write(text)
            block_index += 1
            if rest_file_size >= block_size:
                rest_file_size = rest_file_size - block_size
            else:
                rest_file_size = 0
    f.close()
    time_end = time.time()
    total_file[file_name] = {"last_update_time": os.path.getmtime(file_name),
                             "file_size": get_file_size(file_name)}
    print(file_name, "finish in", time_end - time_start)


# start to request updated file from peer
def request_update_from_peer(file, socket):
    operation_code = 3
    file_name = file
    total_file[file_name] = 1
    f = open(file_name, 'rb+')
    rest_file_size = block_size
    header = struct.pack('!II', operation_code, 0)
    format_data = header + file_name.encode()
    if encryption_on == "yes":
        format_data = encrypt_text(format_data)
    header_length = len(format_data)
    binary_data = struct.pack('!I', header_length) + format_data
    socket.send(binary_data)
    text = b''
    while rest_file_size > 0:
        msg = socket.recv(block_size)
        text += msg
        receive_data_size = len(msg)
        rest_file_size = rest_file_size - receive_data_size
    if encryption_on == "yes":
        text = decrypt_text(text)
    f.write(text)
    f.close()
    total_file[file_name] = {"last_update_time": os.path.getmtime(file_name),
                             "file_size": get_file_size(file_name)}
    print(file_name, "update finish")


# breakpoint resume
def further_transfer(socket, file_name, total_file_size):
    operation_code = 3
    total_file[file_name] = 1
    current_file_size = get_file_size(file_name)
    current_block_index = math.floor(current_file_size / block_size)
    rest_file_size = total_file_size - current_block_index * block_size
    total_block_number = math.ceil(total_file_size / block_size)
    request_block_index = current_block_index
    f = open(file_name, 'rb+')
    f.seek(current_block_index * block_size, 0)
    while rest_file_size > 0:
        if request_block_index <= total_block_number:
            header = struct.pack('!II', operation_code, request_block_index)
            format_data = header + file_name.encode()
            if encryption_on == "yes":
                format_data = encrypt_text(format_data)
            header_length = len(format_data)
            binary_data = struct.pack('!I', header_length) + format_data
            socket.send(binary_data)
        if encryption_on == "no":
            msg = socket.recv(block_size * 3)
            f.write(msg)
            receive_data_size = len(msg)
            rest_file_size = rest_file_size - receive_data_size
            request_block_index += 1
        else:
            if rest_file_size >= block_size:
                rest_for_one_time = block_size
            else:
                rest_for_one_time = math.ceil(rest_file_size / 16) * 16
            text = b''
            while rest_for_one_time > 0:
                msg = socket.recv(rest_for_one_time)
                text += msg
                receive_data_size = len(msg)
                rest_for_one_time = rest_for_one_time - receive_data_size
            text = decrypt_text(text)
            f.write(text)
            request_block_index += 1
            if rest_file_size >= block_size:
                rest_file_size = rest_file_size - block_size
            else:
                rest_file_size = 0
    f.close()
    print("breakpoint resume finish")
    total_file[file_name] = {"last_update_time": os.path.getmtime(file_name),
                             "file_size": get_file_size(file_name)}


# server methods
# this socket is for information exchange
def start_server_socket1():
    while True:
        connection_socket1, addr1 = main_socket1.accept()
        th = threading.Thread(target=sub_connection_for_inform, args=(connection_socket1, addr1,))
        th.start()


# this socket is for data transfer
def start_server_socket2():
    while True:
        connection_socket2, addr2 = main_socket2.accept()
        th = threading.Thread(target=sub_connection_for_transfer, args=(connection_socket2, addr2,))
        th.start()


def sub_connection_for_inform(connection_socket, address):
    while True:
        try:
            msg1 = connection_socket.recv(4)
        except:
            break
        else:
            if not msg1:
                break
            length = struct.unpack('!I', msg1)[0]
            msg1 = connection_socket.recv(length)
            if encryption_on == "yes":
                msg1 = decrypt_text(msg1)
            process_msg_for_inform(msg1, connection_socket, address)


def sub_connection_for_transfer(connection_socket, address):
    while True:
        try:
            msg2 = connection_socket.recv(4)
        except:
            break
        else:
            if not msg2:
                break
            binary_header_length = msg2[:4]
            header_length = struct.unpack('!I', binary_header_length)[0]
            msg2 = connection_socket.recv(header_length)
            if encryption_on == "yes":
                msg2 = decrypt_text(msg2)
            try:
                process_msg_for_transfer(msg2, connection_socket)
            except:
                print(address[0], "offline")
                break


def process_msg_for_inform(msg, connection_socket, address):
    decode_data = json.loads(msg.decode())
    if decode_data["operation_code"] == 0:
        if peer_status[address[0]] == 1:  # 1 means the peer is online, but say hello again, so the peer was killed
            # need to reset the client socket and bind again
            peer_status[address[0]] = 0
            port_list.append(socket_for_peer[address[0]][0].getsockname()[1])
            socket_for_peer[address[0]][0].close()
            port_list.append(socket_for_peer[address[0]][1].getsockname()[1])
            socket_for_peer[address[0]][1].close()
            socket_for_peer[address[0]][0] = socket(AF_INET, SOCK_STREAM)
            socket_for_peer[address[0]][0].setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            socket_for_peer[address[0]][0].bind(("", port_list.pop()))
            socket_for_peer[address[0]][1] = socket(AF_INET, SOCK_STREAM)
            socket_for_peer[address[0]][1].setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            socket_for_peer[address[0]][1].bind(("", port_list.pop()))
        socket_for_peer[address[0]][0].connect((address[0], main_port1))
        socket_for_peer[address[0]][1].connect((address[0], main_port2))
        print(address[0], "online")
        peer_status[address[0]] = 1
        if decode_data["server_operation_code"] == 1:
            update_new_file_from_peer(decode_data, address[0])
        if new_add_file:
            data = {"operation_code": 0, "server_operation_code": 1, "new_add_file": new_add_file}
            format_data = json.dumps(data).encode()
            if encryption_on == "yes":
                format_data = encrypt_text(format_data)
            encode_data = struct.pack('!I', len(format_data)) + format_data
            connection_socket.send(encode_data)
        else:
            data = {"operation_code": 0, "server_operation_code": 0}
            format_data = json.dumps(data).encode()
            if encryption_on == "yes":
                format_data = encrypt_text(format_data)
            encode_data = struct.pack('!I', len(format_data)) + format_data
            connection_socket.send(encode_data)
    elif decode_data["operation_code"] == 1:
        update_new_file_from_peer(decode_data, address[0])
    elif decode_data["operation_code"] == 2:
        for file in decode_data["new_update_file"]:
            if file not in new_update_from_peer:
                new_update_from_peer.append({"file_name": file, "ip_address": address[0]})


def process_msg_for_transfer(msg, connection_socket):
    block_index = struct.unpack('!I', msg[4:8])[0]
    file_name = msg[8:].decode()
    file_block = get_file_block(file_name, block_index)
    if encryption_on == "yes":
        file_block = encrypt_text(file_block)
    connection_socket.send(file_block)


if __name__ == '__main__':
    input_values()
    t1 = threading.Thread(target=start_server_socket1)
    t1.start()
    t2 = threading.Thread(target=start_server_socket2)
    t2.start()
    t3 = threading.Thread(target=detect_change, args=(ip_list,))
    t3.start()
    for i in range(len(ip_list)):
        client_socket1 = socket(AF_INET, SOCK_STREAM)
        client_socket1.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        bind_port1 = port_list.pop()
        client_socket1.bind(("", bind_port1))
        client_socket2 = socket(AF_INET, SOCK_STREAM)
        client_socket2.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        bind_port2 = port_list.pop()
        client_socket2.bind(("", bind_port2))
        socket_for_peer[ip_list[i]] = [client_socket1, client_socket2]
        detect_peer(ip_list[i])
        t4 = threading.Thread(target=detect_new_file_from_peer, args=(ip_list[i],))
        t4.start()
