#!/usr/bin/python
import socket
import thread
import time
import logging
import sys
import struct
import binascii
import uuid
import Queue
import pickle
import datetime
import hashlib

"""
MultiSwitcher
Usage: MultiSwitcher.py <port_number>
Example: MultiSwitcher.py 2099
Bind a port and listen to tcp clients.
links are handled with cooperation of MultiLine. links and services from MultiLine are forwarded to the
machines running MultiSwitcher.

"""


# -------------------------------------------------------------------------------

def ByteToHex(byteStr):
    """
    Convert a byte string to it's hex string representation e.g. for output.
    """

    # Uses list comprehension which is a fractionally faster implementation than
    # the alternative, more readable, implementation below
    #
    #    hex = []
    #    for aChar in byteStr:
    #        hex.append( "%02X " % ord( aChar ) )
    #
    #    return ''.join( hex ).strip()

    return ''.join(["%02X " % ord(x) for x in byteStr]).strip()


# -------------------------------------------------------------------------------

def HexToByte(hexStr):
    """
    Convert a string hex byte values into a byte string. The Hex Byte values may
    or may not be space separated.
    """
    # The list comprehension implementation is fractionally slower in this case
    #
    #    hexStr = ''.join( hexStr.split(" ") )
    #    return ''.join( ["%c" % chr( int ( hexStr[i:i+2],16 ) ) \
    #                                   for i in range(0, len( hexStr ), 2) ] )

    bytes = []

    hexStr = ''.join(hexStr.split(" "))

    for i in range(0, len(hexStr), 2):
        bytes.append(chr(int(hexStr[i:i + 2], 16)))

    return ''.join(bytes)


def PrintUsage():
    print "MultiSwitcher"
    print "Usage: MultiSwitcher.py <port_number>"
    print "Example: MultiSwitcher.py 2099"
    print "Bind a port and listen to tcp clients."
    print "links are handled with cooperation of MultiLine. links and services from " \
          "MultiLine are forwarded to the machines running MultiSwitcher."

class MultiSwitcher:
    def __init__(self, port):
        self.port = port
        #(sock, magicnumber)s are put into links list
        self.links = []

        self.binds = []
        #(magic, cmd, sessionid, <data_str>), data_str is optional. should be handled.
        self.input_q = Queue.Queue()
        # (magic, cmd, sessionid, <data_str>), data_str is optional. should be forwarded to the links.
        self.output_q = Queue.Queue()
        #session write list, sort the disordered packets first. only for data
        #(session_id, sock,  [])  (magic, 'data', sessionid, sn, <data_str>)s are put the write_list of each id.
        #(session, sock, write_list[], magic, refresh_time, running_flag)
        self.write_out_list = []
        self.get_flag = True
        #write input checker threads to check input
        self.input_checker = 3
        #print log flag
        self.p_log = True
        #file log flag
        self.f_log = False
        #timeout 3600 second
        self.timeout = 20
        #interval to check sessions
        self.interval = 10

    @staticmethod
    def new_uuid():
        """Generate new uuid"""
        t_uuid = str(uuid.uuid1()).replace('-', '')
        return HexToByte(t_uuid)

    @staticmethod
    def pack(tuple_data):
        # (self.magic, 'data' or 'close_session', session_uuid, serial_number, t_str)
        if tuple_data[1] == 'data':
            t_len = len(tuple_data[4])
            lendata = struct.pack('>h', t_len)
            s_n = struct.pack('>h', tuple_data[3])
            return tuple_data[0] + tuple_data[1] + tuple_data[2] + s_n + lendata + tuple_data[4]
        if tuple_data[1] == 'close_session':
            s_n = struct.pack('>h', tuple_data[3])
            return tuple_data[0] + 'clos' + tuple_data[2] + s_n
        if tuple_data[1] == 'new_session':
            load_data = pickle.dumps(tuple_data)
            t_len = len(load_data)
            lendata = struct.pack('>h', t_len)
            return tuple_data[0] + 'news' + tuple_data[2] + lendata + load_data
        if tuple_data[1] == 'bind':
            load_data = pickle.dumps(tuple_data)
            t_len = len(load_data)
            lendata = struct.pack('>h', t_len)
            return tuple_data[0] + 'bind' + lendata + load_data
        if tuple_data[1] == 'link_id':
            return tuple_data[0] + 'link'
        return None

    @staticmethod
    def unpack(bytes_data):
        if bytes_data[16:20] == 'data':
            # return (self.magic, 'data', session_uuid, serial_number, t_str)
            command_str = 'data'
            magicnumber = bytes_data[0:16]
            session_id = bytes_data[20:36]
            cnt = struct.unpack('>h', bytes_data[36:38])[0]
            length = struct.unpack('>h', bytes_data[38:40])[0]
            load_data = bytes_data[40:(40 + length)]
            return magicnumber, command_str, session_id, cnt, load_data
        if bytes_data[16:20] == 'clos':
            command_str = 'close_session'
            magicnumber = bytes_data[0:16]
            session_id = bytes_data[20:36]
            cnt = struct.unpack('>h', bytes_data[36:38])[0]
            if len(bytes_data) != 38:
                raise IOError('data format error')
            return magicnumber, command_str, session_id, cnt
        if bytes_data[16:20] == 'news':
            length = struct.unpack('>h', bytes_data[36:38])[0]
            res = pickle.loads(bytes_data[38:38 + length])
            return res
        if bytes_data[16:20] == 'bind':
            length = struct.unpack('>h', bytes_data[20:22])[0]
            res = pickle.loads(bytes_data[22:22 + length])
            return res
        if bytes_data[16:20] == 'link':
            magicnumber = bytes_data[0:16]
            return magicnumber, 'link_id'
        return None

    def s_unpack(self, in_bytes_data):
        res = []
        # return ([tuples], remained_bytes)
        while True:
            t_len = len(in_bytes_data)
            if t_len < 20:
                return (res, in_bytes_data)
            if in_bytes_data[16:20] == 'data' and t_len >= 40:
                length = struct.unpack('>h', in_bytes_data[38:40])[0]
                if t_len >= length + 40:
                    t_tuple = self.unpack(in_bytes_data[0:length + 40])
                    res.append(t_tuple)
                    in_bytes_data = in_bytes_data[length + 40:t_len]
                    continue
                else:
                    return (res, in_bytes_data)
            if in_bytes_data[16:20] == 'clos':
                if t_len >= 38:
                    t_tuple = self.unpack(in_bytes_data[0:38])
                    res.append(t_tuple)
                    in_bytes_data = in_bytes_data[38:t_len]
                    continue
                else:
                    return (res, in_bytes_data)
            if in_bytes_data[16:20] == 'link':
                if t_len >= 20:
                    t_tuple = self.unpack(in_bytes_data[0:20])
                    res.append(t_tuple)
                    in_bytes_data = in_bytes_data[20:t_len]
                    continue
                else:
                    return (res, in_bytes_data)
            if in_bytes_data[16:20] == 'news' and t_len >= 38:
                length = struct.unpack('>h', in_bytes_data[36:38])[0]
                if t_len >= (38 + length):
                    t_tuple = self.unpack(in_bytes_data[0:38 + length])
                    res.append(t_tuple)
                    in_bytes_data = in_bytes_data[38 + length:t_len]
                    continue
                else:
                    return (res, in_bytes_data)
            if in_bytes_data[16:20] == 'bind' and t_len >= 22:
                length = struct.unpack('>h', in_bytes_data[20:22])[0]
                if t_len >= (22 + length):
                    t_tuple = self.unpack(in_bytes_data[0:22 + length])
                    res.append(t_tuple)
                    in_bytes_data = in_bytes_data[22 + length:t_len]
                    continue
                else:
                    return (res, in_bytes_data)
            return (res, in_bytes_data)

    @staticmethod
    def tuple_msg(tuple_data):
        res = 'Type:<' + tuple_data[1] + '> session:' + ByteToHex(tuple_data[2])
        if tuple_data[1] == 'data' or tuple_data[1] == 'close_session':
            res = res + ' idx:<' + str(tuple_data[3]) + '>'
        if tuple_data[1] == 'data':
            m = hashlib.md5()
            m.update(tuple_data[4])
            res = res + ' hexdigest:' + m.hexdigest()
        return res

    def pf_log(self, info_str):
        if self.p_log:
            t_str = str(datetime.datetime.now()) + ' ' + str(info_str)
            print t_str
        if self.f_log:
            logging.info(str(info_str))

    #Clear all links and lists.
    def clear(self):
        for (sock, magicnumber) in self.links:
            try:
                sock.close()
            except Exception, e:
                pass
        self.links = []
        for sock in self.binds:
            try:
                sock.close()
            except Exception, e:
                pass
        self.binds = []

    def start(self):
        while True:
            try:
                dock_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dock_socket.bind(('', self.port))
                dock_socket.listen(7)
                for i in range(self.input_checker):
                    thread.start_new_thread(self.check_input_q, ())
                thread.start_new_thread(self.check_output_q, ())
                #thread.start_new_thread(self.check_session, (self.interval,))
                while True:
                    client_socket = dock_socket.accept()[0]
                    self.pf_log(
                        'new client added:' + str(client_socket.getpeername()))
                    thread.start_new_thread(self.check_link, (client_socket,))
            except Exception, e:
                self.pf_log(e)
                self.pf_log('restart multiswitcher ' + str(self.port))
            finally:
                self.clear()
                time.sleep(5)

    def check_input_q(self):
        while True:
            try:
                t_in = self.input_q.get(True,None)
                self.parse_input_data(t_in)
            except Queue.Empty, e:
                pass
            except Exception, e:
                pass

    def parse_input_data(self, data):
        """Parse in data, if forward needed, forward them to the client"""
        try:
            cnt = 0
            #(magic, cmd, sessionid, < data_str >)
            while True:
                if cnt > 1:
                    return
                for (ss_id, sock, w_list, magic, refresh_time, run_flag) in self.write_out_list:
                    if ss_id == data[2]:
                        w_list.append(data)
                        return
                cnt += 1
        except Exception, e:
            return

    def check_output_q(self):
        idx = 0
        counter = 0
        self.get_flag = True
        while True:
            try:
                if len(self.links) == 0:
                    time.sleep(0.1)
                    continue
                if idx > (len(self.links) - 1):
                    idx = 0
                if self.get_flag:
                    t_send = self.output_q.get(True,None)
                    counter=0
                (sock, magicnumber) = self.links[idx]
                counter += 1
                if magicnumber == t_send[0]:
                    try:
                        out = self.pack(t_send)
                        sock.sendall(out)
                        self.pf_log('write line =>' + self.tuple_msg(t_send))
                        self.get_flag = True
                    except Exception, e:
                        self.get_flag = False
                        self.pf_log(e)
                        try:
                            sock.close()
                            self.links.remove((sock, magicnumber))
                        except Exception, e:
                            pass
                        finally:
                            pass
                if counter > len(self.links):
                    self.get_flag = True
                idx += 1
            except Exception, e:
                pass

    def valid_link_magic(self, magic):
        res = False
        for (sock, magicnumber) in self.links:
            if magicnumber == magic:
                res = True
        return res

    #useless, this make it disconnected at timeout. refresh_time doesn't work.
    def check_session(self, interval):
        while True:
            time.sleep(interval)
            for session_list in self.write_out_list:
                current_time = datetime.datetime.now()
                (session, sock, write_list, magic, refresh_time, run_flag) = session_list
                if (current_time - refresh_time).total_seconds() > self.timeout:
                    try:
                        sock.close()
                    except Exception, e:
                        pass
                    finally:
                        try:
                            self.write_out_list.remove(session_list)
                        except Exception, e:
                            pass
                        self.pf_log('Close session:' + ByteToHex(session))

    def check_link(self, link_sock):
        try:
            remain = ''
            while True:
                t_data = link_sock.recv(4096)
                if not t_data:
                    raise IOError('Network Error')
                if t_data == HexToByte(
                        '47 45 54 20 2F 20 48 54 54 50 2F 31 2E 31 0D 0A 0D 0A'):  # GET / HTTP/1.1  'ingore these connections
                    try:
                        link_sock.close()
                    except Exception, e:
                        self.pf_log(e)
                    finally:
                        raise IOError('Wrong data, close!')
                try:
                    (t_reses, remain) = self.s_unpack(remain + t_data)
                    while len(t_reses) > 0:
                        t_res = t_reses[0]
                        command = t_res[1]
                        if command == 'data' or command == 'close_session':
                        # only data are put into input_q
                            self.input_q.put(t_res)
                            t_reses.remove(t_res)
                            continue
                        if command == 'link_id':
                            #put (sock, magicnumber) in links
                            self.links.append((link_sock, t_res[0]))
                            t_reses.remove(t_res)
                            continue
                        if command == 'new_session':
                            thread.start_new_thread(self.new_session, (t_res,))
                            t_reses.remove(t_res)
                            continue
                        if command == 'bind':
                            thread.start_new_thread(self.bind_server, (t_res[0], t_res[2], t_res[3]))
                            t_reses.remove(t_res)
                            continue
                        t_reses.remove(t_res)
                except Exception, e:
                    pass
        except Exception, e:
            self.pf_log(e)
            try:
                link_sock.close()
            except Exception, e:
                pass
            for (sock, magicnumber) in self.links:
                if sock is link_sock:
                    try:
                        self.links.remove((sock, magicnumber))
                    except Exception, e:
                        pass

    def new_session(self, session_conf):
        try:
            (t_magic, t_cmd, t_session, t_dest, t_port) = session_conf
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((t_dest, t_port))
            # ('t_session', [])
            run_flag = True
            refresh_time = datetime.datetime.now()
            session_list = (t_session, sock, [], t_magic, refresh_time, run_flag)
            self.write_out_list.append(session_list)
            # check all the received data and put it in input queue.
            thread.start_new_thread(self.forward_session, session_list)
            thread.start_new_thread(self.session_write, session_list)
        except Exception, e:
            pass
        finally:
            return

    def remove_magic(self, magic_number):
        pass

    def remove_session(self, session_id):
        for item in self.write_out_list:
            t_session, sock, w_list, t_magic, refresh_time, run_flag = item
            if t_session == session_id:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except Exception, e:
                    pass
                try:
                    self.write_out_list.remove(item)
                except Exception, e:
                    pass
                sock = None
                self.pf_log("Remove session: " + ByteToHex(session_id) + "   Finnished.")

    def session_write(self, session, sock, write_list, t_magic, refresh_time, run_flag):
        idx = 0
        while True:
            if sock is None:
                return
            if len(write_list) == 0:
                time.sleep(0.3)
                continue
            #(magicnumber, command_str, session_id, cnt, load_data)
            for tuple_data in write_list:
                if tuple_data[3] == idx:
                    if tuple_data[1] == 'data':
                        try:
                            sock.sendall(tuple_data[4])
                            write_list.remove(tuple_data)
                            refresh_time = datetime.datetime.now()
                            self.pf_log('>>>>>>>>>>>>>>>>>>>>>>session_write->' + self.tuple_msg(tuple_data))
                            idx += 1
                            if idx == 32768:
                                idx = 0
                            break
                        except Exception, e:
                            self.remove_session(session)
                            return
                    if tuple_data[1] == 'close_session':
                        self.remove_session(session)
                        return

    def bind_server(self, magic, host, port):
        """local server at local_addr:local_port. All links are forwarded to remote_addr:remote_port"""
        while True:
            try:
                if not self.valid_link_magic(magic):
                    return
                (b_addr, b_port) = (host, port)
                dock_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dock_socket.bind((b_addr, b_port))
                dock_socket.listen(5)
                self.binds.append(dock_socket)
                while True:
                    dock_socket.settimeout(5)
                    try:
                        client_socket = dock_socket.accept()[0]
                    except Exception, e:
                        if not self.valid_link_magic(magic):
                            # raise error to close the connections.
                            raise IOError('Client disconnected!')
                        else:
                            continue
                    #client_socket.setblocking(True)
                    session_uuid = self.new_uuid()
                    b_new_session = (magic, 'new_session', session_uuid)
                    self.output_q.put(b_new_session)
                    self.pf_log('new client added:' + str(client_socket.getpeername()))
                    refresh_time = datetime.datetime.now()
                    #(magicnumber, sock, session_id)
                    run_flag = True
                    session_list = (session_uuid, client_socket, [], magic, refresh_time, run_flag)
                    self.write_out_list.append(session_list)
                    thread.start_new_thread(self.session_write, session_list)
                    thread.start_new_thread(self.serve_client, session_list)
                    #todo If magic doesn't exist in the links, this server should be closed.
            except Exception, e:
                self.pf_log(e)
                time.sleep(0.5)
            finally:
                try:
                    dock_socket.close()
                except Exception, e:
                    pass
                try:
                    self.binds.remove(dock_socket)
                except Exception, e:
                    pass
                return

    def serve_client(self, session_uuid, client_socket, w_list, magic, refresh_time, run_flag):
        inited = False
        client_socket.setblocking(False)
        client_socket.settimeout(5)
        try:
            sn = 0
            while True:
                try:
                    t_str = client_socket.recv(1024)
                except Exception, e:
                    if not self.valid_link_magic(magic):
                        raise IOError('Client link disconnected!')
                    else:
                        continue
                if not t_str:
                    if inited:
                        raise IOError('Client closed')
                if len(t_str) > 0:
                    #(magic, cmd, sessionid, sn, < data_str >)
                    bc_data = (magic, 'data', session_uuid, sn, t_str)
                    inited = True
                    self.output_q.put(bc_data)
                    sn += 1
                    if sn == 32768:
                        sn = 0
                else:
                    time.sleep(0.2)
        except Exception, e:
            self.pf_log(e)
        finally:
            try:
                self.output_q.put((magic, 'close_session', session_uuid, sn))
                client_socket.close(socket.SHUT_RD)
            except Exception, e:
                pass
            finally:
                pass

    def forward_session(self, t_session, sock, w_list, t_magic, refresh_time, run_flag):
        try:
            inited = False
            sn = 0
            while True:
                in_data = sock.recv(1024)
                if not in_data:
                    if inited:
                        raise IOError('Client closed')
                if len(in_data) > 0:
                    inited = True
                    #(magic, cmd, sessionid, sn, <data_str>)
                    self.output_q.put((t_magic, 'data', t_session, sn, in_data))
                    refresh_time = datetime.datetime.now()
                    in_data = ''
                    sn += 1
                    if sn == 32768:
                        sn = 0
        except Exception, e:
            pass
        finally:
            self.output_q.put((t_magic, 'close_session', t_session, sn))
            try:
                sock.shutdown(socket.SHUT_RD)
            except Exception, e:
                pass

if __name__ == '__main__':
    try:
        in_port = sys.argv[1]
        log_file = 'log_MultiSwitcher'+'_'+in_port+'.txt'
        FORMAT = '%(asctime)-15s %(message)s'
        logging.basicConfig(filename=log_file, level=logging.DEBUG, format=FORMAT)
        in_port = int(in_port)
        t_switcher = MultiSwitcher(in_port)
        t_switcher.start()
    except Exception, e:
        PrintUsage()
        sys.exit()
    while True:
        time.sleep(5)
