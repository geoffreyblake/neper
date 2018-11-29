/*
 * Copyright 2016 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "control_plane.h"
#include <czmq.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <unistd.h>
#include "common.h"
#include "hexdump.h"
#include "lib.h"
#include "logging.h"
#include "thread.h"

static int recv_magic(int fd, struct callbacks *cb, const char *fn)
{
        int n, magic = 0;

        while ((n = read(fd, &magic, sizeof(magic))) == -1) {
                if (errno == EINTR || errno == EAGAIN)
                        continue;
                NP_PLOG_FATAL(cb, "%s: read", fn);
        }
        if (n != sizeof(magic))
                NP_LOG_FATAL(cb, "%s: Incomplete read %d", fn, n);
        return ntohl(magic);
}

static void send_magic(int fd, int magic, struct callbacks *cb, const char *fn)
{
        int n;

        magic = htonl(magic);
        while ((n = write(fd, &magic, sizeof(magic))) == -1) {
                if (errno == EINTR || errno == EAGAIN)
                        continue;
                NP_PLOG_FATAL(cb, "%s: write", fn);
        }
        if (n != sizeof(magic))
                NP_LOG_FATAL(cb, "%s: Incomplete write %d", fn, n);
}

static const char control_port_secret[] = "neper control port secret";
#define SECRET_SIZE (sizeof(control_port_secret))

static int ctrl_connect(const char *host, const char *port,
                        struct addrinfo **ai, struct options *opts,
                        struct callbacks *cb)
{
        int ctrl_conn, magic, optval = 1;
        ctrl_conn = try_connect(host, port, ai, opts, cb);
        if (setsockopt(ctrl_conn, IPPROTO_TCP, TCP_NODELAY, &optval,
                       sizeof(optval)))
                NP_PLOG_ERROR(cb, "setsockopt(TCP_NODELAY)");
        while (write(ctrl_conn, control_port_secret, SECRET_SIZE) == -1) {
                if (errno == EINTR)
                        continue;
                NP_PLOG_FATAL(cb, "write");
        }
        /* if authentication passes, server should write back a magic number */
        magic = recv_magic(ctrl_conn, cb, __func__);
        if (magic != opts->magic)
                NP_LOG_FATAL(cb, "magic mismatch: %d != %d", magic, opts->magic);
        return ctrl_conn;
}

static int ctrl_listen(const char *host, const char *port,
                       struct addrinfo **ai, struct options *opts,
                       struct callbacks *cb)
{
        struct addrinfo *result, *rp;
        int flags = AI_PASSIVE;
        int fd_listen = 0;

        result = do_getaddrinfo(host, port, flags, opts, cb);
        for (rp = result; rp != NULL; rp = rp->ai_next) {
                fd_listen = socket(rp->ai_family, rp->ai_socktype,
                                   rp->ai_protocol);
                if (fd_listen == -1) {
                        NP_PLOG_ERROR(cb, "socket");
                        continue;
                }
                set_reuseport(fd_listen, cb);
                set_reuseaddr(fd_listen, 1, cb);
                if (bind(fd_listen, rp->ai_addr, rp->ai_addrlen) == 0)
                        break;
                NP_PLOG_ERROR(cb, "bind");
                do_close(fd_listen);
        }
        if (rp == NULL)
                NP_LOG_FATAL(cb, "Could not bind");
        *ai = copy_addrinfo(rp);
        freeaddrinfo(result);
        if (listen(fd_listen, opts->listen_backlog))
                NP_PLOG_FATAL(cb, "listen");
        return fd_listen;
}

static int ctrl_accept(int ctrl_port, int *num_incidents, struct callbacks *cb,
                       int magic)
{
        char buf[1024], dump[8192], host[NI_MAXHOST], port[NI_MAXSERV];
        struct sockaddr_storage cli_addr;
        socklen_t cli_len;
        int ctrl_conn, s;
        ssize_t len;
retry:
        cli_len = sizeof(cli_addr);
        while ((ctrl_conn = accept(ctrl_port, (struct sockaddr *)&cli_addr,
                                   &cli_len)) == -1) {
                if (errno == EINTR || errno == ECONNABORTED)
                        continue;
                NP_PLOG_FATAL(cb, "accept");
        }
        s = getnameinfo((struct sockaddr *)&cli_addr, cli_len,
                        host, sizeof(host), port, sizeof(port),
                        NI_NUMERICHOST | NI_NUMERICSERV);
        if (s) {
                NP_LOG_ERROR(cb, "getnameinfo: %s", gai_strerror(s));
                strcpy(host, "(unknown)");
                strcpy(port, "(unknown)");
        }
        memset(buf, 0, sizeof(buf));
        while ((len = read(ctrl_conn, buf, sizeof(buf))) == -1) {
                if (errno == EINTR)
                        continue;
                NP_PLOG_ERROR(cb, "read");
                do_close(ctrl_conn);
                goto retry;
        }
        if (memcmp(buf, control_port_secret, SECRET_SIZE) != 0) {
                if (num_incidents)
                        (*num_incidents)++;
                if (hexdump(buf, len, dump, sizeof(dump))) {
                        NP_LOG_WARN(cb, "Invalid secret from %s:%s\n%s", host,
                                 port, dump);
                } else
                        NP_LOG_WARN(cb, "Invalid secret from %s:%s", host, port);
                do_close(ctrl_conn);
                goto retry;
        }
        /* tell client that authentication passes */
        send_magic(ctrl_conn, magic, cb, __func__);
        NP_LOG_INFO(cb, "Control connection established with %s:%s", host, port);
        return ctrl_conn;
}

static void ctrl_wait_client(int ctrl_conn, int expect, struct callbacks *cb)
{
        int magic;

        while ((magic = recv_magic(ctrl_conn, cb, __func__)) != expect)
                NP_LOG_WARN(cb, "Unexpected magic %d", magic);
}

static void ctrl_notify_server(int ctrl_conn, int magic, struct callbacks *cb)
{
        send_magic(ctrl_conn, magic, cb, __func__);
        if (shutdown(ctrl_conn, SHUT_WR))
                NP_PLOG_ERROR(cb, "shutdown");
}

#if 0
// XXX: This is a brittle way to ping-pong readiness among peers -- need to make it
// more robust I think for general usage
static void peer_ctrl_send_peer(int peer_conn, int magic, struct callbacks *cb) 
{
        send_magic(peer_conn, magic, cb, __func__);
}

static void peer_ctrl_wait(int peer_conn, int expect, struct callbacks *cb)
{
        int magic;
        while ((magic = recv_magic(peer_conn, cb, __func__)) != expect)
                NP_LOG_WARN(cb, "Unexpected magic %d", magic);
}
#endif

struct control_plane {
        struct options *opts;
        struct callbacks *cb;
        int num_incidents;
        struct host *hosts;
        int *ctrl_conn;
        int num_hosts;
        int ctrl_port;
};

struct peer_control {
        struct options *opts;
        struct callbacks *cb;
        struct host *slaves;
        zsock_t **peer_conn;
        int num_slaves;
        int peer_port;
};

struct control_plane* control_plane_create(struct options *opts,
                                           struct callbacks *cb)
{
        struct control_plane *cp;

        cp = calloc(1, sizeof(*cp));
        cp->opts = opts;
        cp->cb = cb;
        return cp;
}

struct peer_control* peer_control_create(struct options *opts,
                                        struct callbacks *cb)
{
        struct peer_control *pc;

        pc = calloc(1, sizeof(*pc));
        pc->opts = opts;
        pc->cb = cb;
        return pc;
}

void control_plane_start(struct control_plane *cp, struct addrinfo **ai)
{
        if (cp->opts->client) {
                // This needs to be updated to connect to multiple hosts
                cp->num_hosts = hosts_len(cp->opts->host);
                cp->hosts = cp->opts->host;
                cp->ctrl_conn = (int*)malloc(cp->num_hosts * sizeof(int));

                for (int i = 0; i < cp->num_hosts; i++) {
                        cp->ctrl_conn[i] = ctrl_connect(cp->hosts[i].host_name,
                                                        cp->hosts[i].ctrl_port, &ai[i],
                                                        cp->opts, cp->cb);
                        NP_LOG_INFO(cp->cb, "connected to control port on %s:%d", cp->hosts[i].host_name,
                                 cp->hosts[i].ctrl_port);
                }
                
        } else {
                cp->ctrl_port = ctrl_listen(NULL, cp->opts->control_port, ai,
                                            cp->opts, cp->cb);
                NP_LOG_INFO(cp->cb, "opened control port");
        }
}

struct serialized_hosts 
{
        char host_name[256];
        char ctrl_port[64];
        char data_port[64];
};

struct host* peer_control_start(struct peer_control *pc)
{
        int rc;
        struct host *h = NULL;
        if (pc->opts->client) {
                if (pc->opts->slave_mode) {
                        pc->peer_conn = (zsock_t **)malloc(sizeof(zsock_t *));
                        char endpoint[256];
                        if (snprintf(endpoint, 256, "tcp://*:%s", pc->opts->peer_port) < 0) {
                                NP_LOG_FATAL(pc->cb, "failed to define bind address");
                        }
                        pc->peer_conn[0] = zsock_new_rep(endpoint);
                        if (pc->peer_conn == NULL) {
                                NP_LOG_FATAL(pc->cb, "failed to bind to %s with 0MQ", endpoint);
                        }
                        NP_LOG_INFO(pc->cb, "opened peer port");

                        // Now we need to get info about our control plane targets for SUTs
                        zmsg_t *hosts_ser = zmsg_recv(pc->peer_conn[0]);
                        if (hosts_ser == NULL) {
                                NP_LOG_FATAL(pc->cb, "Something happened on receiving message");
                        }
                        int num_hosts = zmsg_size(hosts_ser);
                        h = (struct host *)calloc(num_hosts + 1, sizeof(struct host));
                        for (int i = 0; i < num_hosts; i++) {
                                zframe_t *frame = zmsg_pop(hosts_ser);
                                if (zframe_size(frame) < sizeof(struct serialized_hosts)) {
                                        NP_LOG_FATAL(pc->cb, "Did not recieve a host data-structure?!");
                                }
                                struct serialized_hosts *sh = (struct serialized_hosts*)zframe_data(frame);
                                h[i] = (struct host){ .host_name = strdup(sh->host_name),
                                                .ctrl_port = strdup(sh->ctrl_port),
                                                .data_port = strdup(sh->data_port) };
                        }
                        h[num_hosts] = (struct host) { .host_name = NULL,
                                                .ctrl_port = NULL,
                                                .data_port = NULL };
                        zmsg_destroy(&hosts_ser);

                        // Send back an ACK to master to notify we received data
                        zmsg_t *msg = zmsg_new();
                        zframe_t *frame = zframe_from("ACK");
                        zmsg_append(msg, &frame);
                        rc = zmsg_send(&msg, pc->peer_conn[0]);
                        if (rc != 0) {
                                NP_LOG_FATAL(pc->cb, "ZSend failed");
                        }
                        
                } else {
                        pc->num_slaves = hosts_len(pc->opts->slaves);
                        pc->slaves = pc->opts->slaves;
                        pc->peer_conn = (zsock_t **)calloc(pc->num_slaves, sizeof(zsock_t*));

                        for (int i = 0; i < pc->num_slaves; i++) {
                                char endpoint[256];
                                if (snprintf(endpoint, 256, "tcp://%s:%s", pc->slaves[i].host_name,
                                                        pc->slaves[i].ctrl_port) < 0) {
                                        NP_LOG_FATAL(pc->cb, "something went wrong defining endpoint");
                                }

                                pc->peer_conn[i] = zsock_new_req(endpoint);
                                if (pc->peer_conn[i] == NULL) {
                                        NP_LOG_FATAL(pc->cb, "failed to connect to %s", endpoint);
                                }
                                NP_LOG_INFO(pc->cb, "connected to peer port on %s:%s", pc->slaves[i].host_name,
                                         pc->slaves[i].ctrl_port);

                                zmsg_t *msg = zmsg_new();
                                zframe_t *frame;
                                for (int j = 0; j < hosts_len(pc->opts->host); j++) { 
                                        struct serialized_hosts s;
                                        strncpy(s.host_name, pc->opts->host[j].host_name, 256);
                                        strncpy(s.ctrl_port, pc->opts->host[j].ctrl_port, 64);
                                        strncpy(s.data_port, pc->opts->host[j].data_port, 64);
                                        frame = zframe_new(&s, sizeof(s));

                                        zmsg_append(msg, &frame);
                                }
                                // Send the hosts to our slaves
                                rc = zmsg_send(&msg, pc->peer_conn[i]);
                                if (rc != 0) {
                                        NP_LOG_FATAL(pc->cb, "ZSend failed");
                                } 

                                // wait for peer to send back a message to for receipt
                                msg = zmsg_recv(pc->peer_conn[i]);
                                char *m = zmsg_popstr(msg);
                                if (strcmp("ACK", m)) {
                                        NP_LOG_FATAL(pc->cb, "Something is out of sync passing hosts!: %s", m);
                                }
                                // Ok, we're sync'ed with our peer, lets go!
                                zmsg_destroy(&msg);
                                free(m);
                        }
                }
        }
        return h;
}

void peer_control_wait_for_signal(struct peer_control *pc) {
        int rc;
        if (pc->opts->client) {
                if (pc->opts->slave_mode) {
                        NP_LOG_INFO(pc->cb, "expecting a peer notification");
                        
                        // Get notification from leader its ready
                        zmsg_t *msg;
                        zframe_t *frame;
                        msg = zmsg_recv(pc->peer_conn[0]);
                        
                        // Tell leader we're ready
                        assert(zmsg_size(msg) == 1); // should only be 1 frame
                        char *m = zmsg_popstr(msg);
                        if (strcmp("GO", m)) {
                                NP_LOG_FATAL(pc->cb, "Something is out of sync!");
                        }
                        zmsg_destroy(&msg);
                        free(m);

                        msg = zmsg_new();
                        frame = zframe_from("ACK");
                        zmsg_append(msg, &frame);

                        rc = zmsg_send(&msg, pc->peer_conn[0]);
                        if (rc != 0) {
                                NP_LOG_FATAL(pc->cb, "ZSend failed");
                        }
                         
                        NP_LOG_INFO(pc->cb, "received notification");
                } else {
                        // Send all the peers a notification leader is ready
                        for (int i = 0; i < pc->num_slaves; i++) {
                                zframe_t *frame = zframe_from("GO");
                                zmsg_t *msg = zmsg_new();
                                zmsg_append(msg, &frame);

                                rc = zmsg_send(&msg, pc->peer_conn[i]);
                                if (rc != 0) {
                                        NP_LOG_FATAL(pc->cb, "ZSend failed");
                                }
                                NP_LOG_INFO(pc->cb, "sending notification");
                        }
 
                        for (int i = 0; i < pc->num_slaves; i++) {
                                zmsg_t *msg = zmsg_recv(pc->peer_conn[i]);
                                assert(zmsg_size(msg) == 1);
                                char *m = zmsg_popstr(msg);
                                if (strcmp("ACK", m)) {
                                        NP_LOG_FATAL(pc->cb, "Something is out of sync!");
                                }
                                NP_LOG_INFO(pc->cb, "receiving acks");
                                free(m);
                        }
                        // XXX: Not a perfect distributed barrier, it is rather naive, so there will
                        // be some start time skew as the number of peers goes up.  Do I have to worry about keeping
                        // a barrier count to avoid deadlock?
                }
        }
} 

// Very minimal stats transfer protocol of just transactions sent/recv'ed
struct mini_stats {
        int transactions;
        int sent_transactions;
};

// XXX: This needs to be updated
void peer_control_wait_for_stats(struct peer_control *pc, struct thread *tinfo) {
        int i, rc;
        if (pc->opts->client) {
                if (pc->opts->slave_mode) {
                        zmsg_t *msg;
                        zframe_t *frame;
                        struct mini_stats s;
                        s.transactions = 0;
                        s.sent_transactions = 0;
                        for (i = 0; i < pc->opts->num_threads; i++) {
                               s.transactions += tinfo[i].transactions;
                               s.sent_transactions += tinfo[i].sent_transactions;
                        }

                        msg = zmsg_recv(pc->peer_conn[0]);
                        char *m = zmsg_popstr(msg);
                        if (strcmp(m, "SENDSTATS")) {
                                NP_LOG_FATAL(pc->cb, "Something is out of sync!");
                        }
                        zmsg_destroy(&msg);

                        msg = zmsg_new();
                        frame = zframe_new(&s, sizeof(s));
                        zmsg_append(msg, &frame); 
                       
                        rc = zmsg_send(&msg, pc->peer_conn[0]);
                        if (rc != 0) {
                                NP_LOG_FATAL(pc->cb, "ZSend failed");
                        }
                } else {
                        struct mini_stats agg;
                        agg.transactions = 0;
                        agg.sent_transactions = 0;

                        // Tell our peers to send us their stats
                        for (int i = 0; i < pc->num_slaves; i++) {
                                zmsg_t *msg = zmsg_new();
                                zmsg_pushstr(msg, "SENDSTATS");
                                zmsg_send(&msg, pc->peer_conn[i]);
                        }

                        for (int i = 0; i < pc->num_slaves; i++) {
                                zmsg_t *msg = zmsg_recv(pc->peer_conn[i]);
                                zframe_t *frame = zmsg_pop(msg);
                                struct mini_stats *s = (struct mini_stats*)zframe_data(frame);

                                agg.transactions += s->transactions;
                                agg.sent_transactions += s->sent_transactions;
                                zmsg_destroy(&msg);
                        }
                        PRINT(pc->cb, "peer transactions:", "%d", agg.transactions);
                        PRINT(pc->cb, "peer sent transactions:", "%d", agg.sent_transactions);
                }
        }
}

void control_plane_wait_until_done(struct control_plane *cp)
{
        if (cp->opts->client) {
                sleep(cp->opts->test_length);
                NP_LOG_INFO(cp->cb, "finished sleep");
        } else {
                const int n = cp->opts->num_clients;
                int* client_fds = calloc(n, sizeof(int));
                int i;

                if (!client_fds)
                        NP_PLOG_FATAL(cp->cb, "calloc client_fds");
                NP_LOG_INFO(cp->cb, "expecting %d clients", n);
                for (i = 0; i < n; i++) {
                        client_fds[i] = ctrl_accept(cp->ctrl_port,
                                                    &cp->num_incidents, cp->cb,
                                                    cp->opts->magic);
                        NP_LOG_INFO(cp->cb, "client %d connected", i);
                }
                do_close(cp->ctrl_port);  /* disallow further connections */
                if (cp->opts->nonblocking) {
                        for (i = 0; i < n; i++)
                                set_nonblocking(client_fds[i], cp->cb);
                }
                NP_LOG_INFO(cp->cb, "expecting %d notifications", n);
                for (i = 0; i < n; i++) {
                        ctrl_wait_client(client_fds[i], cp->opts->magic,
                                         cp->cb);
                        NP_LOG_INFO(cp->cb, "received notification %d", i);
                }
                for (i = 0; i < n; i++)
                        do_close(client_fds[i]);
                free(client_fds);
        }
}

void control_plane_stop(struct control_plane *cp)
{
        if (cp->opts->client) {
            for (int i = 0; i < cp->num_hosts; i++) {
                ctrl_notify_server(cp->ctrl_conn[i], cp->opts->magic, cp->cb);
                NP_LOG_INFO(cp->cb, "notified server to exit");
                do_close(cp->ctrl_conn[i]);
            }
        }
}

int control_plane_incidents(struct control_plane *cp)
{
        return cp->num_incidents;
}

void control_plane_destroy(struct control_plane *cp)
{
        free(cp);
}

void peer_control_destroy(struct peer_control *pc) {
        if (pc->opts->client) {
                if (pc->opts->slave_mode) {
                        zsock_destroy(&pc->peer_conn[0]);
                        free(pc->peer_conn);
                } else {
                        for (int i = 0; i < pc->num_slaves; i++) {
                                zsock_destroy(&pc->peer_conn[i]);
                        }
                        free(pc->peer_conn);
                }
        }
        free(pc);
}
