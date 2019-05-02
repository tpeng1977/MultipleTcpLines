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
    print "Usage: MultiLine.py -s <server:port> -n <n_lines> -c <command> " \
          "-l local_addr:local_port:remote_addr:remote_port"
    print "command: R forward a local_address:local_port to remote_addr:remote_port"
    print "command: L bind a remote_addr:remote_port to local_addr:local_port"
    print "Example: MultiLine.py -s localhost:4999 -n 5 -c L -l 127.0.0.1:7080:localhost:80"
    print "Example: MultiLine.py -s localhost:4999 -n 5 -c R -l 127.0.0.1:80:0.0.0.0:6080"
    print "The above two examples bind remote service to local and bind local service to remote."
    print "Must be used with MultiSwitcher.py"


class MultiClient:
    def __init__(self, server_addr, n_lines, cmd_str, (local_addr, local_port, remote_addr, remote_port)):
        self.server_addr = server_addr
        self.n_lines = n_lines
        self.cmd = cmd_str
        self.rl_link = (local_addr, local_port, remote_addr, remote_port)
        t_uuid = str(uuid.uuid1()).replace('-', '')
        self.magic = HexToByte(t_uuid)
        self.input_q = Queue.Queue()
        self.output_q = Queue.Queue()
        self.socks = []
        self.threads = []
        #(sock, session_id)s are put in the following lists. Clients received at this machine are put in local_clients.
        #self.local_clients = []
        # (sock, session_id)s are put in the following lists. Clients forwarded from remote machine are put in remote_links.
        #self.remote_links = []
        # session write list, sort the disordered packets first. only for data
        # (session_id, sock,  [])  (magic, 'data', sessionid, sn, <data_str>)s are put the list of each id.
        self.write_out_list = []
        # write input checker threads to check input
        self.input_checker = 10
        self.output_checker = 10
        # print log flag
        self.p_log = True
        # file log flag
        self.f_log = False


    def link_id(self):
        """Generate link id for all the links to the server. """
        return self.pack((self.magic, 'link_id'))

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
            res = pickle.loads(bytes_data[38:38+length])
            return res
        if bytes_data[16:20] == 'bind':
            length = struct.unpack('>h', bytes_data[20:22])[0]
            res = pickle.loads(bytes_data[22:22+length])
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
                    t_tuple = self.unpack(in_bytes_data[0:38+length])
                    res.append(t_tuple)
                    in_bytes_data = in_bytes_data[38+length:t_len]
                    continue
                else:
                    return (res, in_bytes_data)
            if in_bytes_data[16:20] == 'bind' and t_len >= 22:
                length = struct.unpack('>h', in_bytes_data[20:22])[0]
                if t_len >= (22+length):
                    t_tuple = self.unpack(in_bytes_data[0:22+length])
                    res.append(t_tuple)
                    in_bytes_data = in_bytes_data[22+length:t_len]
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

    def start_links(self):
        for i in range(self.n_lines):
            t_id = thread.start_new_thread(self.a_link, (i, ))
            self.threads.append(t_id)
        for i in range(self.input_checker):
            thread.start_new_thread(self.check_input, ())
        for i in range(self.output_checker):
            thread.start_new_thread(self.check_output, ())

        time.sleep(2)
        if self.cmd == 'L':
            thread.start_new_thread(self.local_server, ())
        if self.cmd == 'R':
            self.output_q.put((self.magic, 'bind', self.rl_link[2], self.rl_link[3]))
        pass

    def check_input(self):
        while True:
            try:
                t_in = self.input_q.get(True, None)
                self.parse_in_data(t_in)
            except Queue.Empty, e:
                pass
            except Exception, e:
                pass

    def parse_in_data(self, data):
        """Parse in data, if forward needed, forward them to the client"""
        try:
            #(magic, cmd, sessionid, < data_str >)
            while True:
                for (ss_id, sock, w_list) in self.write_out_list:
                    if ss_id == data[2]:
                        w_list.append(data)
                        return
                time.sleep(0.2)
        except Exception, e:
            pass

    def valid_session(self, session_id):
        for (t_session, sock, w_list) in self.write_out_list:
            if t_session == session_id:
                return True
        return False

    def remove_session(self, session_id):
        for item in self.write_out_list:
            t_session, sock, w_list = item
            if t_session == session_id:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except Exception, e:
                    pass
                try:
                    self.write_out_list.remove(item)
                except Exception, e:
                    pass
                sock = None
                self.pf_log("Remove session: " + ByteToHex(session_id) + "   Finnished.")

    def session_write(self, session, sock, write_list):
        idx = 0
        refresh_time = datetime.datetime.now()
        while True:
            if len(write_list) == 0:
                if not self.valid_session(session):
                    return
                time.sleep(0.3)
                continue
            min_idx = 32769
            # (magicnumber, command_str, session_id, cnt, load_data)
            for tuple_data in write_list:
                if min_idx > tuple_data[3]:
                    min_idx = tuple_data[3]
                if tuple_data[3] == idx:
                    if tuple_data[1] == 'data':
                        try:
                            refresh_time = datetime.datetime.now()
                            sock.sendall(tuple_data[4])
                            write_list.remove(tuple_data)
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
            if (datetime.datetime.now() - refresh_time).total_seconds() > 8 and min_idx != idx:
                self.remove_session(session)
                return

    def forward_session(self, sock, session):
        self.serve_client(sock, session)
        return

    def check_output(self):
        idx = 0
        get_flag = True
        t_send = None
        while True:
            try:
                if len(self.socks) == 0:
                    time.sleep(1)
                    continue
                if idx > (len(self.socks) - 1):
                    idx = 0
                if get_flag:
                    t_send = self.output_q.get(True, None)
                t_sock = self.socks[idx]
                if t_send is not None:
                    t_sock.sendall(self.pack(t_send))
                    self.pf_log('write line =>' + self.tuple_msg(t_send))
                get_flag = True
                idx += 1
            except Exception, e:
                get_flag = False
                self.pf_log(e)
                try:
                    t_sock.shutdown(socket.SHUT_RDWR)
                    self.socks.remove(t_sock)
                    time.sleep(0.25)
                except Exception, e:
                    pass
                finally:
                    pass

    def a_link(self, idx, ):
        while True:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(self.server_addr)
                self.socks.append(sock)
                sock.sendall(self.link_id())
                remain = ''
                while True:
                    t_data = sock.recv(4096)
                    if not t_data:
                        raise IOError('Link socket closed!')
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
                            if command == 'new_session':
                                # todo: Do following in a new thread may result in better performance.
                                tl_session_id = t_res[2]
                                tl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                tl_sock.connect((self.rl_link[0], self.rl_link[1]))
                                tl_session_list = (tl_session_id, tl_sock, [])
                                self.write_out_list.append(tl_session_list)
                                thread.start_new_thread(self.session_write, tl_session_list)
                                thread.start_new_thread(self.forward_session, (tl_sock, tl_session_id))
                                t_reses.remove(t_res)
                                continue
                            t_reses.remove(t_res)
                    except Exception, e:
                        pass

            except Exception, e:
                self.pf_log(e)
                time.sleep(5)
            finally:
                try:
                    sock.close()
                    self.socks.remove(sock)
                except Exception, e:
                    pass
                finally:
                    pass

    def local_server(self):
        """local server at local_addr:local_port. All links are forwarded to remote_addr:remote_port"""
        while True:
            try:
                (l_addr, l_port) = (self.rl_link[0], self.rl_link[1])
                dock_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dock_socket.bind((l_addr, l_port))
                dock_socket.listen(5)
                while True:
                    client_socket = dock_socket.accept()[0]
                    session_uuid = self.new_uuid()
                    self.output_q.put((self.magic, 'new_session', session_uuid, self.rl_link[2], self.rl_link[3]))
                    nc_session_list = (session_uuid, client_socket, [])
                    self.write_out_list.append(nc_session_list)
                    thread.start_new_thread(self.session_write, nc_session_list)
                    time.sleep(0.5)
                    thread.start_new_thread(self.serve_client, (client_socket, session_uuid))
            except Exception, e:
                self.pf_log(e)
                time.sleep(0.5)
            finally:
                try:
                    dock_socket.close()
                except Exception, e:
                    pass
                finally:
                    pass

    def serve_client(self, client_socket, session_uuid, ):
        # start_time = datetime.datetime.now()
        inited = False
        sn = 0
        try:
            while True:
                t_str = client_socket.recv(1024)
                if not t_str:
                    #current_time = datetime.datetime.now()
                    if inited:# and ((current_time - start_time).total_seconds() > 10):
                        raise IOError('Client disconnected!')
                    if len(t_str) == 0:
                        time.sleep(0.02)
                        continue
                else:
                    self.output_q.put((self.magic, 'data', session_uuid, sn, t_str))
                    inited = True
                    #start_time = datetime.datetime.now()
                    sn += 1
                    if sn == 32768:
                        sn = 0
        except Exception, e:
            self.pf_log(e)
        finally:
            try:
                self.output_q.put((self.magic, 'close_session', session_uuid, sn))
                #self.local_clients.remove((client_socket, session_uuid))
                client_socket.shutdown(socket.SHUT_RDWR)
            except Exception, e:
                pass
            finally:
                pass


if __name__ == '__main__':
    try:
        (server_host, server_port) = sys.argv[sys.argv.index('-s') + 1].split(":")
        command = sys.argv[sys.argv.index('-c') + 1]
        (local_addr, local_port, remote_addr, remote_port) = sys.argv[sys.argv.index('-l') + 1].split(":")
        local_port = int(local_port)
        remote_port = int(remote_port)
        if command != 'R' and command != 'L':
            raise Exception('wrong command parameter!')
        server_port = int(server_port)
        n_lines = int(sys.argv[sys.argv.index('-n') + 1])
    except Exception, e:
        PrintUsage()
        sys.exit()

    log_file = 'log_MultiLine'+'.txt'
    FORMAT = '%(asctime)-15s %(message)s'
    logging.basicConfig(filename=log_file, level=logging.DEBUG, format=FORMAT)
    mc = MultiClient((server_host, server_port), n_lines, command, (local_addr, local_port, remote_addr, remote_port))
    mc.start_links()

    while True:
        time.sleep(5)
