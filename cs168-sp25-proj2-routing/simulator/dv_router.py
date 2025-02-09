"""
Your awesome Distance Vector router for CS 168

Based on skeleton code by:
  MurphyMc, zhangwen0411, lab352
"""

import sim.api as api
from cs168.dv import (
    RoutePacket,
    Table,
    TableEntry,
    DVRouterBase,
    Ports,
    FOREVER,
    INFINITY,
)


class DVRouter(DVRouterBase):

    # A route should time out after this interval
    ROUTE_TTL = 15

    # -----------------------------------------------
    # At most one of these should ever be on at once
    SPLIT_HORIZON = False
    POISON_REVERSE = False
    # ----------------------------------------------

    # Determines if you send poison for expired routes
    POISON_EXPIRED = False

    # Determines if you send updates when a link comes up
    SEND_ON_LINK_UP = False

    # Determines if you send poison when a link goes down
    POISON_ON_LINK_DOWN = False

    def __init__(self):
        """
        Called when the instance is initialized.
        DO NOT remove any existing code from this method.
        However, feel free to add to it for memory purposes in the final stage!
        """
        assert not (
            self.SPLIT_HORIZON and self.POISON_REVERSE
        ), "Split horizon and poison reverse can't both be on"

        self.start_timer()  # Starts signaling the timer at correct rate.

        # Contains all current ports and their latencies.
        # See the write-up for documentation.
        self.ports = Ports()

        # This is the table that contains all current routes
        self.table = Table()
        self.table.owner = self

        ##### Begin Stage 10A #####
        from collections import defaultdict
        self.history = defaultdict(dict)  # port -> {dst: latency}
        ##### End Stage 10A #####

    def add_static_route(self, host, port):
        """
        Adds a static route to this router's table.

        Called automatically by the framework whenever a host is connected
        to this router.

        :param host: the host.
        :param port: the port that the host is attached to.
        :returns: nothing.
        """
        # `port` should have been added to `peer_tables` by `handle_link_up`
        # when the link came up.
        assert port in self.ports.get_all_ports(), "Link should be up, but is not."

        ##### Begin Stage 1 #####
        self.table[host] = TableEntry(dst=host, port=port, latency=self.ports.get_latency(port), expire_time=FOREVER)
        ##### End Stage 1 #####

    def handle_data_packet(self, packet, in_port):
        """
        Called when a data packet arrives at this router.

        You may want to forward the packet, drop the packet, etc. here.

        :param packet: the packet that arrived.
        :param in_port: the port from which the packet arrived.
        :return: nothing.
        """
        
        ##### Begin Stage 2 #####
        if packet.dst not in self.table:
            return
        
        if self.table[packet.dst].latency >= INFINITY:
            return
        
        self.send(packet, port=self.table[packet.dst].port)
        ##### End Stage 2 #####

    def _send_route(self, port, dst, latency, force=False):
        if not force:
            if self.history[port].get(dst, None) == latency:
                return
        self.send_route(port, dst, latency)
        self.history[port][dst] = latency

    def send_routes(self, force=False, single_port=None):
        """
        Send route advertisements for all routes in the table.

        :param force: if True, advertises ALL routes in the table;
                      otherwise, advertises only those routes that have
                      changed since the last advertisement.
               single_port: if not None, sends updates only to that port; to
                            be used in conjunction with handle_link_up.
        :return: nothing.
        """
        
        ##### Begin Stages 3, 6, 7, 8, 10 #####
        if single_port is not None:
            ports = [single_port]
        else:
            ports = self.ports.get_all_ports()

        for route in self.table.values():
            for port in ports:
                if port == route.port:
                    if self.SPLIT_HORIZON:
                        continue
                    if self.POISON_REVERSE:
                        self._send_route(port, route.dst, INFINITY, force)
                        continue
                # count to infinity
                latency = min(route.latency, INFINITY)
                self._send_route(port, route.dst, latency, force)
        ##### End Stages 3, 6, 7, 8, 10 #####

    def expire_routes(self):
        """
        Clears out expired routes from table.
        accordingly.
        """
        
        ##### Begin Stages 5, 9 #####
        expired_hosts = []
        for h, entry in self.table.items():
            if api.current_time() >= entry.expire_time:
                expired_hosts.append(h)
        for h in expired_hosts:
            if self.POISON_EXPIRED:
                entry = self.table[h]
                self.table[h] = TableEntry(dst=entry.dst, port=entry.port, latency=INFINITY, expire_time=api.current_time() + self.ROUTE_TTL)
            else:
                self.table.pop(h)
        ##### End Stages 5, 9 #####

    def handle_route_advertisement(self, route_dst, route_latency, port):
        """
        Called when the router receives a route advertisement from a neighbor.

        :param route_dst: the destination of the advertised route.
        :param route_latency: latency from the neighbor to the destination.
        :param port: the port that the advertisement arrived on.
        :return: nothing.
        """
        
        ##### Begin Stages 4, 10 #####
        port_latency = self.ports.get_latency(port)
        latency = port_latency + route_latency
        new_entry = TableEntry(dst=route_dst, port=port, latency=latency, expire_time=api.current_time()+self.ROUTE_TTL)
        if route_dst not in self.table:
            # always accept a new destination advertisement
            self.table[route_dst] = new_entry
            self.send_routes(force=False)
        else:
            entry = self.table[route_dst]
            if entry.port == port:
                # update from next-hop
                self.table[route_dst] = new_entry
                self.send_routes(force=False)
            elif latency < entry.latency:
                # Bellman-ford update
                self.table[route_dst] = new_entry
                self.send_routes(force=False)
            else:
                pass
        ##### End Stages 4, 10 #####

    def handle_link_up(self, port, latency):
        """
        Called by the framework when a link attached to this router goes up.

        :param port: the port that the link is attached to.
        :param latency: the link latency.
        :returns: nothing.
        """
        self.ports.add_port(port, latency)

        ##### Begin Stage 10B #####
        if self.SEND_ON_LINK_UP:
            self.send_routes(force=True, single_port=port)
        ##### End Stage 10B #####

    def handle_link_down(self, port):
        """
        Called by the framework when a link attached to this router goes down.

        :param port: the port number used by the link.
        :returns: nothing.
        """
        self.ports.remove_port(port)

        ##### Begin Stage 10B #####
        down_routes = []
        for h, entry in self.table.items():
            if entry.port == port:
                down_routes.append(h)

        for h in down_routes:
            entry = self.table[h]
            if self.POISON_ON_LINK_DOWN:
                self.table[h] = TableEntry(dst=entry.dst, port=port, latency=INFINITY, expire_time=api.current_time()+self.ROUTE_TTL)
                self.send_routes(force=False)
            else:
                self.table.pop(h)
        ##### End Stage 10B #####

    # Feel free to add any helper methods!
