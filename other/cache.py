#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Monster Hunter cache module.

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

from mh.time_utils import Timer
from mh.session import Session
from mh.state import get_instance, Server
from other.utils import Logger, create_logger, get_remote_config, \
        get_central_config, get_config, get_ip

from threading import Lock
import socket
import struct
import logging
import json

try:
    # Python 3
    import selectors
except ImportError:
    # Python 2
    import externals.selectors2 as selectors


class PacketTypes(object):
    FriendlyHello = 0x0001
    ReqConnectionInfo = 0x0002
    SendConnectionInfo = 0x0003
    ReqServerRefresh = 0x0004
    SessionInfo = 0x0005
    ServerIDList = 0x0006
    ServerShutdown = 0x0007


class CentralConnectionHandler(object):
    def __init__(self, socket, client_address, cache):
        self.id = -1
        self.socket = socket
        self.client_address = client_address
        self.cache = cache
        self.rfile = self.socket.makefile('rb', -1)
        self.wfile = self.socket.makefile('wb', 0)

        self.rw = Lock()
        self.finished = False

        self.handler_functions = {
            PacketTypes.FriendlyHello: self.RecvFriendlyHello,
            PacketTypes.SendConnectionInfo: self.RecvConnectionInfo,
            PacketTypes.ReqConnectionInfo: self.RecvReqConnectionInfo,
            PacketTypes.ReqServerRefresh: self.RecvReqServerRefresh,
            PacketTypes.SessionInfo: self.RecvSessionInfo,
            PacketTypes.ServerShutdown: self.RecvServerShutdown,
        }

    def fileno(self):
        # type: () -> int
        return self.socket.fileno()

    def on_recv(self):
        header = self.rfile.read(10)
        if not len(header) or len(header) < 10:
            return None

        return self.recv_packet(header)

    def recv_packet(self, header):
        size, packet_id, server_id = struct.unpack(">IIH", header)
        data = self.rfile.read(size)
        return server_id, packet_id, data

    def send_packet(self, packet_id=0, data=b""):
        self.wfile.write(self.pack_data(
            data, packet_id
        ))

    def pack_data(self, data, packet_id):
        return struct.pack(">II", len(data), packet_id) + data

    def is_finished(self):
        return self.finished

    def on_exception(self, e):
        self.finish()

    def direct_to_handler(self, packet):
        server_id, packet_type, data = packet
        self.handler_functions[packet_type](server_id, data)

    def RecvFriendlyHello(self, server_id, data):
        self.cache.debug("Recieved a friendly hello from {}!".format(
            server_id
        ))
        self.cache.register_handler(server_id, self)
        self.ReqConnectionInfo()

    def ReqConnectionInfo(self):
        self.cache.debug("Requesting connection info.")
        self.send_packet(PacketTypes.ReqConnectionInfo, b"")

    def RecvConnectionInfo(self, server_id, data):
        self.cache.debug("Recieved connection info sized {} from {}".format(
            len(data), server_id
        ))
        server = Server.deserialize(json.loads(data))
        self.cache.servers[server_id] = server
        self.cache.update_players()

    def RecvReqConnectionInfo(self, server_id, data):
        requested_server_id, = struct.unpack(">H", data)
        self.cache.debug("Recieved request for data of Server {}.".format(
            requested_server_id
        ))
        if server_id in self.cache.servers:
            data = json.dumps(self.cache.servers[server_id].serialize())
            self.SendConnectionInfo(data)

    def SendConnectionInfo(self, data):
        self.cache.debug("Sending updated connection info.")
        self.send_packet(PacketTypes.SendConnectionInfo, data)

    def RecvReqServerRefresh(self, server_id, data):
        self.cache.debug("Recieved server refresh request from \
                          Server {}.".format(
            server_id
        ))
        self.SendServerIDList()
        for _server_id in self.cache.servers:
            data = struct.pack(">H", _server_id)
            data += json.dumps(self.cache.servers[_server_id].serialize())
            self.SendConnectionInfo(data)

    def SendServerIDList(self):
        self.cache.debug("Sending updated Server ID list.")
        data = struct.pack(">H", self.cache.servers_version)
        data += struct.pack(">H", len(self.cache.servers))
        for _server_id in self.cache.servers:
            data += struct.pack(">H", _server_id)
        self.send_packet(PacketTypes.ServerIDList, data)

    def RecvSessionInfo(self, server_id, data):
        dest_server_id, = struct.unpack(">H", data[:2])
        self.cache.debug("Recieved session data from Server {} \
                            bound for Server {}.".format(
            server_id, dest_server_id
        ))
        self.cache.update_player_record(
            Session.deserialize(json.loads(data[2:]))
        )
        self.cache.get_handler(dest_server_id).SendSessionInfo(data[2:])

    def SendSessionInfo(self, ser_session):
        self.send_packet(PacketTypes.SessionInfo, ser_session)

    def RecvServerShutdown(self, server_id, data):
        raise Exception("Server shutting down.")

    def finish(self):
        if self.finished:
            return

        self.finished = True

        try:
            self.wfile.close()
        except Exception:
            pass

        try:
            self.rfile.close()
        except Exception:
            pass

        try:
            self.socket.close()
        except Exception:
            pass


class RemoteConnectionHandler(object):
    def __init__(self, socket, client_address, cache):
        self.id = 0
        self.socket = socket
        self.client_address = client_address
        self.cache = cache
        self.rfile = self.socket.makefile('rb', -1)
        self.wfile = self.socket.makefile('wb', 0)

        self.rw = Lock()
        self.finished = False

        self.handler_functions = {
            PacketTypes.ReqConnectionInfo: self.ReqConnectionInfo,
            PacketTypes.SendConnectionInfo: self.RecvConnectionInfo,
            PacketTypes.SessionInfo: self.RecvSessionInfo,
            PacketTypes.ServerIDList: self.RecvServerIDList,
        }

    def fileno(self):
        # type: () -> int
        return self.socket.fileno()

    def on_recv(self):
        header = self.rfile.read(8)
        if not len(header) or len(header) < 8:
            return None

        return self.recv_packet(header)

    def recv_packet(self, header):
        size, packet_id = struct.unpack(">II", header)
        data = self.rfile.read(size)
        return packet_id, data

    def is_finished(self):
        return self.finished

    def on_exception(self, e):
        self.finish()

    def send_packet(self, packet_id=0, data=b""):
        self.wfile.write(self.pack_data(
            data, packet_id
        ))

    def pack_data(self, data, packet_id):
        return struct.pack(">IIH", len(data), packet_id,
                           self.cache.server_id) + data

    def direct_to_handler(self, packet):
        packet_type, data = packet
        self.handler_functions[packet_type](data)

    def SendFriendlyHello(self, data=b""):
        self.cache.debug("Sending a friendly hello!")
        self.send_packet(PacketTypes.FriendlyHello, data)

    def ReqConnectionInfo(self, data):
        self.cache.debug("Recieved request for update connection \
                          info from Central.")
        data = json.dumps(get_instance().server.serialize())
        self.SendConnectionInfo(data)

    def SendConnectionInfo(self, data):
        self.cache.debug("Sending connection info to Central.")
        self.send_packet(PacketTypes.SendConnectionInfo, data)

    def SendReqServerRefresh(self):
        self.cache.debug("Requesting refreshed server info from central.")
        self.send_packet(PacketTypes.ReqServerRefresh, b"")

    def SendReqConnectionInfo(self, server_id):
        self.cache.debug("Requesting info for Server {}".format(
            server_id
        ))
        self.send_packet(PacketTypes.ReqConnectionInfo,
                         struct.pack(">H", server_id))

    def RecvServerIDList(self, data):
        self.cache.debug("Recieved updated Server ID list from Central.")
        servers_version, count = struct.unpack(">HH", data[:4])
        self.cache.update_servers_version(servers_version)
        updated_server_ids = []
        for i in range(count):
            server_id = struct.unpack(">H", data[2*(i+2):2*(i+2)+2])
            updated_server_ids.append(server_id)
        for server_id in self.cache.servers.keys():
            if server_id not in updated_server_ids:
                self.cache.prune_server(server_id)

    def RecvConnectionInfo(self, data):
        try:
            server_id, = struct.unpack(">H", data[:2])
            server = Server.deserialize(json.loads(data[2:]))
        except Exception as e:
            self.cache.error(e)
            return
        self.cache.debug("Obtained updated server info for Server {}".format(
            server_id
        ))
        self.cache.servers[server_id] = server

    def SendSessionInfo(self, server_id, ser_session):
        self.cache.debug("Sending Session info to Server {}".format(
            server_id
        ))
        data = struct.pack(">H", server_id)
        data += ser_session
        self.send_packet(PacketTypes.SessionInfo, data)

    def RecvSessionInfo(self, data):
        self.cache.debug("Recieved new Session info!")
        self.cache.new_session(Session.deserialize(json.loads(data)))

    def finish(self):
        if self.finished:
            return

        self.finished = True

        try:
            self.wfile.close()
        except Exception:
            pass

        try:
            self.rfile.close()
        except Exception:
            pass

        try:
            self.socket.close()
        except Exception:
            pass


class Cache(Logger):
    def __init__(self, server_id, debug_mode=False, log_to_file=False,
                 log_to_console=False, log_to_window=False,
                 refresh_period=30, use_ssl=True,
                 ssl_location='cert/crossserverCA/'):
        Logger.__init__(self)
        self.servers_version = 1
        self.servers = {
            # To be populated by remote connection
        }

        self.outbound_sessions = [
            # (destination_server_id, session)
        ]

        self.players = {
            # capcom_id -> connectionless sessions from other servers
        }
        self.ready_sessions = {
            # pat_ticket -> True or connection_data
        }
        self.set_logger(create_logger("Cache",
                                      level=logging.DEBUG
                                      if debug_mode else logging.INFO,
                                      log_to_file="cache.log" if log_to_file
                                      else "",
                                      log_to_console=log_to_console,
                                      log_to_window=log_to_window))

        self.is_central_server = server_id == 0
        if not self.is_central_server:
            remote_config = get_remote_config("SERVER{}".format(server_id))
            get_instance().setup_server(server_id,
                                        remote_config["Name"],
                                        int(remote_config["ServerType"]),
                                        int(remote_config["Capacity"]),
                                        get_ip(remote_config["IP"]),
                                        int(remote_config["Port"]))
        else:
            config = get_config("FMP")
            get_instance().setup_server(
                server_id, "", 0, 1, '0.0.0.0', config["Port"]
            )
        self.shut_down = False
        self.refresh_period = refresh_period
        self.handlers = {}
        self.server_id = server_id
        central_config = get_central_config()
        self.central_connection = (central_config["CentralIP"],
                                   central_config["CentralCrossconnectPort"])
        self.sel = selectors.DefaultSelector()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if use_ssl:
            import ssl
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            if self.is_central_server:
                context.load_verify_locations(
                    cafile="{}ca.crt".format(ssl_location)
                )
                context.load_cert_chain("{}MH3SP.crt".format(ssl_location),
                                        "{}MH3SP.key".format(ssl_location))
            else:
                context.load_cert_chain(
                    "{}client{}.crt".format(ssl_location, server_id),
                    "{}client{}.key".format(ssl_location, server_id)
                )
            self.socket = context.wrap_socket(
                self.socket, server_side=self.is_central_server
            )

    def update_player_record(self, session):
        get_instance().update_capcom_id(session)

    def update_players(self):
        players = []
        for server_id, server in self.servers.items():
            if server_id != self.server_id:
                players = players + server.get_all_players()
        new_players = {}
        for p in players:
            new_players[p.capcom_id] = p
        self.players = new_players
        if self.is_central_server:
            get_instance().update_players()

    def update_servers_version(self, servers_version):
        self.servers_version = servers_version

    def get_server_list(self, include_ids=False):
        if include_ids:
            return list(self.servers.keys()), list(self.servers.values())
        return list(self.servers.values())

    def get_server(self, server_id):
        assert server_id in self.servers
        return self.servers[server_id]

    def send_session_info(self, server_id, session):
        self.outbound_sessions.append(
            (server_id, json.dumps(session.serialize()))
        )

    def new_session(self, session):
        ready_data = self.session_ready(session.pat_ticket)
        if ready_data:
            self.set_session_ready(session.pat_ticket, False)
            get_instance().register_pat_ticket(session)
            self.send_login_packet(*ready_data)
            
        else:
            get_instance().register_pat_ticket(session)
            self.set_session_ready(session.pat_ticket, True)

    def session_ready(self, pat_ticket):
        return self.ready_sessions.get(pat_ticket, False)

    def set_session_ready(self, pat_ticket, store_data):
        self.ready_sessions[pat_ticket] = store_data

    def send_login_packet(self, player_handler, connection_data, seq):
        player_handler.sendNtcLogin(3, connection_data, seq)

    def get_handler(self, server_id):
        return self.handlers[server_id]

    def register_handler(self, server_id, handler):
        handler.id = server_id
        self.handlers[server_id] = handler

    def prune_server(self, server_id):
        for player in self.servers[server_id].get_all_players():
            if player.capcom_id in self.players:
                del self.players[player.capcom_id]
        if server_id != 0:
            del self.servers[server_id]
        if self.is_central_server:
            self.update_servers_version(self.servers_version + 1)

    def maintain_connection(self):
        state = get_instance()
        state.initialized.wait()
        state.cache = self
        get_instance().cache = self
        refresh_timer = Timer()
        if self.is_central_server:
            # CENTRAL SERVER CONNECTION TO REMOTE
            try:
                self.socket.bind(self.central_connection)
                self.socket.listen(0)
            except:
                self.close()
                raise
            self.info("Listening for remote Servers on {}".format(
                self.central_connection
            ))
            self.socket.setblocking(False)
            self.sel.register(self.socket, selectors.EVENT_READ, data=None)
            try:
                self.maintain_central_server(refresh_timer)
            except KeyboardInterrupt:
                self.info(
                    "Keyboard interrupt, disconnecting from remote servers"
                )
            except Exception as e:
                if not self.shut_down:
                    self.error(e)
            finally:
                self.close()
        else:
            # REMOTE SERVER CONNECTION TO CENTRAL
            self.info("Connecting to central server at {}...".format(
                self.central_connection
            ))
            self.socket.setblocking(True)
            self.socket.connect_ex((
                "localhost" if self.central_connection[0] == "0.0.0.0"
                else self.central_connection[0],
                self.central_connection[1]
            ))
            events = selectors.EVENT_READ | selectors.EVENT_WRITE
            self.sel.register(self.socket, events)
            try:
                self.maintain_remote_server(refresh_timer)
            except KeyboardInterrupt:
                self.info(
                    "Keyboard interrupt, disconnecting from remote servers"
                )
            except Exception as e:
                if not self.shut_down:
                    self.error(e)
            finally:
                self.close()

    def maintain_central_server(self, refresh_timer):
        while not self.shut_down:
            events = self.sel.select(timeout=1)
            # 1: Respond to incoming packets
            for key, event in events:
                connection = key.fileobj
                if connection == self.socket:
                    # Accept a new connection
                    client_socket, client_address = connection.accept()
                    self.info("Remote Server connected from {}".format(
                        client_address
                    ))
                    client_socket.setblocking(1)
                    handler = CentralConnectionHandler(client_socket,
                                                       client_address,
                                                       self)
                    self.sel.register(handler, selectors.EVENT_READ)
                    self.update_servers_version(self.servers_version + 1)
                else:
                    assert event == selectors.EVENT_READ
                    try:
                        packet = connection.on_recv()
                        if packet is None:
                            if connection.is_finished():
                                self.remove_handler(connection)
                            continue
                        connection.direct_to_handler(packet)
                    except Exception as e:
                        self.info("Connection to Remote Server \
                            {} lost.".format(
                            connection.id
                        ))
                        connection.on_exception(e)
                        if connection.is_finished():
                            self.remove_handler(connection)
            if refresh_timer.elapsed() >= self.refresh_period:
                try:
                    for _, handler in self.handlers.items():
                        handler.ReqConnectionInfo()
                finally:
                    refresh_timer.restart()
            # 2: Pass on an outbound session
            if len(self.outbound_sessions):
                outbound_session = self.outbound_sessions.pop(0)
                self.get_handler(outbound_session[0]).SendSessionInfo(
                    outbound_session[1]
                )

    def maintain_remote_server(self, refresh_timer):
        while not self.shut_down:
            events = self.sel.select(timeout=3)
            # 1: Respond to incoming packets
            for key, event in events:
                connection = key.fileobj
                if connection == self.socket:
                    # Connection forged
                    handler = RemoteConnectionHandler(
                        self.socket,
                        get_ip(self.central_connection[0]),
                        self
                    )
                    self.sel.unregister(self.socket)
                    self.sel.register(handler, selectors.EVENT_READ)
                    self.handlers[0] = handler
                    handler.SendFriendlyHello()
                elif event & selectors.EVENT_READ:
                    try:
                        packet = connection.on_recv()
                        if packet is None:
                            if connection.is_finished():
                                self.remove_handler(connection)
                            continue
                        connection.direct_to_handler(packet)
                    except Exception as e:
                        connection.on_exception(e)
                        if connection.is_finished():
                            self.remove_handler(connection)
            # 2: Request updated server information
            if refresh_timer.elapsed() >= self.refresh_period:
                try:
                    self.handlers[0].SendReqServerRefresh()
                finally:
                    refresh_timer.restart()
            # 3: Pass on an outbound session
            if len(self.outbound_sessions):
                connection.SendSessionInfo(*self.outbound_sessions.pop(0))

    def remove_handler(self, handler):
        # type: (BasicPatHandler) -> None
        if handler.id > -1:
            try:
                del self.handlers[handler.id]
            except Exception:
                pass

        try:
            self.sel.unregister(handler)
        except Exception:
            pass

        try:
            handler.finish()
        except Exception:
            pass

        try:
            handler.socket.close()
        except Exception:
            pass

        self.prune_server(handler.id)

        if self.is_central_server:
            for handler in self.handlers.values():
                try:
                    handler.SendServerIDList()
                except Exception:
                    self.error("Failed to send the \
                        Server ID list to a handler.")

    def close(self):
        if not self.shut_down:
            self.shut_down = True
            self.socket.close()
            self.sel.close()
            for _, h in self.handlers.items():
                if not self.is_central_server:
                    h.send_packet(PacketTypes.ServerShutdown, b"")
                try:
                    h.finish()
                except Exception:
                    pass
            self.info('Server Closed')
