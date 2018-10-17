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

#include <assert.h>
#include <math.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "common.h"
#include "flow.h"
#include "interval.h"
#include "lib.h"
#include "numlist.h"
#include "percentiles.h"
#include "sample.h"
#include "thread.h"


static inline void track_write_time(struct options *opts, struct flow *flow, struct mmsghdr *buf)
{
        int i;
        struct timespec tm;
        clock_gettime(CLOCK_MONOTONIC, &tm);

        for (i = 0; i < opts->burst_size; i++) {
                *((double*)(buf[i].msg_hdr.msg_iov[0].iov_base)) = (double)((double)tm.tv_sec * 1e9 + (double)tm.tv_nsec);
        }
}

static inline void track_finish_time(int num_pkts, struct flow *flow, struct mmsghdr *buf)
{
        struct timespec finish_time;
        int i;
        double tm, diff;

        diff = 0.0;
        clock_gettime(CLOCK_MONOTONIC, &finish_time);
        tm = (double)finish_time.tv_sec * 1e9 + (double)finish_time.tv_nsec;

        // Grab the first valid sample for now
        for (i = 0; i < num_pkts; i++) {
               diff = tm - *((double*)(buf[i].msg_hdr.msg_iov[0].iov_base));
               if (diff > 0.0)
                       break;
               else
                       diff = 0.0;
        }

        if (diff > 0.0) 
                numlist_add(flow->latency, diff * 1e-9);
}

static void client_events(struct thread *t, int epfd,
                          struct epoll_event *events, int nfds, 
                          struct mmsghdr *buf)
{
        struct options *opts = t->opts;
        struct callbacks *cb = t->cb;
        struct flow *flow;
        ssize_t num_bytes;
        int i;

        for (i = 0; i < nfds; i++) {
                flow = events[i].data.ptr;
                if (flow->fd == t->stop_efd) {
                        t->stop = 1;
                        break;
                }

                if (events[i].events & EPOLLIN) {
                        int flags = 0;

                        num_bytes = recvmmsg(flow->fd, buf, opts->burst_size, flags, NULL);
                        
                        if (num_bytes == -1) {
                                NP_PLOG_ERROR(cb, "read");
                                continue;
                        }
                        
                        flow->bytes_read += num_bytes * opts->packet_size;
                        
                        t->transactions += num_bytes;
                        flow->transactions += num_bytes;
                        
                        track_finish_time(num_bytes, flow, buf);
                        interval_collect(flow, t);

                        events[i].events = EPOLLOUT | EPOLLET | EPOLLONESHOT;
                        epoll_ctl_or_die(epfd, EPOLL_CTL_MOD, flow->fd, &events[i], cb);
                }
                if (events[i].events & EPOLLOUT) {
                        int flags = 0;

                        track_write_time(opts, flow, buf);
                        
                        num_bytes = sendmmsg(flow->fd, buf, opts->burst_size, flags);
                        if (num_bytes == -1) {
                                NP_PLOG_ERROR(cb, "write");
                                num_bytes = 0;
                        }

                        flow->sent_transactions += num_bytes;
                        t->sent_transactions += num_bytes;

                        events[i].events = EPOLLIN | EPOLLET | EPOLLONESHOT;
                        epoll_ctl_or_die(epfd, EPOLL_CTL_MOD, flow->fd, &events[i], cb);
                }
                
        }
}

static struct mmsghdr *buf_alloc(struct options *opts, bool is_server)
{
        int i;
        struct mmsghdr *buf = (struct mmsghdr*)calloc(opts->burst_size, sizeof(struct mmsghdr));
        
        for (i = 0; i < opts->burst_size; i++) {
                buf[i].msg_hdr.msg_name = NULL;
                buf[i].msg_hdr.msg_namelen = 0;

                if (is_server) {
                        buf[i].msg_hdr.msg_name = (struct sockaddr *)malloc(sizeof(struct sockaddr));
                        buf[i].msg_hdr.msg_namelen = sizeof(struct sockaddr);
                }
                buf[i].msg_hdr.msg_control = NULL;
                buf[i].msg_hdr.msg_controllen = 0;
                buf[i].msg_hdr.msg_flags = 0;
                buf[i].msg_hdr.msg_iov = (struct iovec*)calloc(1, sizeof(struct iovec));
                buf[i].msg_hdr.msg_iovlen = 1;
                
                // Figure out the max size of our buffer
                int sz = opts->packet_size;
                buf[i].msg_hdr.msg_iov[0].iov_base = (char*)malloc(sz);
                buf[i].msg_hdr.msg_iov[0].iov_len = sz;
        }

        return buf;
}


static void client_connect_udp(int i, int epfd, struct thread *t)
{
        struct options *opts = t->opts;
        struct callbacks *cb = t->cb;
        struct addrinfo *ai = t->ai[i];
        struct flow *flow;
        int fd; 

        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == -1)
            NP_PLOG_FATAL(cb, "socket");
        if (opts->debug)
            set_debug(fd, 1, cb);
        if (opts->local_host)
            set_local_host(fd, opts, cb);
        if (do_connect(fd, ai->ai_addr, ai->ai_addrlen))
            NP_PLOG_FATAL(cb, "do_connect");

        // Since this is a max-send test, whatever the socket can do, do it as fast
        // as we can.
        flow = addflow_udp(t->index, epfd, fd, i, EPOLLOUT | EPOLLET | EPOLLONESHOT, opts, cb);
        flow->bytes_to_write = opts->request_size;
        flow->itv = interval_create(opts->interval, t);
}


static void run_client(struct thread *t)
{
        struct options *opts = t->opts;
        const int flows_in_this_thread = flows_in_thread(opts->num_flows,
                                                         opts->num_threads, 
                                                         t->index);
        struct callbacks *cb = t->cb;
        struct epoll_event *events;
        int epfd, i;
        struct mmsghdr *buf;

        NP_LOG_INFO(cb, "flows_in_this_thread=%d", flows_in_this_thread);
        epfd = epoll_create1(0);
        if (epfd == -1)
                NP_PLOG_FATAL(cb, "epoll_create1");
        epoll_add_or_die(epfd, t->stop_efd, EPOLLIN, cb);
        // Connect a UDP socket to each client
        if (opts->rr_hosts) {
                client_connect_udp(t->index, epfd, t);
        } else {
                for (i = 0; i < t->num_hosts; i++) {
                        client_connect_udp(i, epfd, t);
                }
        }
        events = calloc(opts->maxevents, sizeof(struct epoll_event));
        buf = buf_alloc(opts, false);
        pthread_barrier_wait(t->ready);
        while (!t->stop) {
                int ms = opts->nonblocking ? 10 /* milliseconds */ : -1;
                int nfds = epoll_wait(epfd, events, opts->maxevents, ms);
                if (nfds == -1) {
                        if (errno == EINTR)
                                continue;
                        NP_PLOG_FATAL(cb, "epoll_wait");
                }
                client_events(t, epfd, events, nfds, buf);
        }
        free(buf);
        free(events);
        do_close(epfd);
}

static void server_events(struct thread *t, int epfd,
                          struct epoll_event *events, int nfds, int fd_listen,
                          struct mmsghdr *buf)
{
        struct options *opts = t->opts;
        struct callbacks *cb = t->cb;
        ssize_t snd_num_bytes, rcv_num_bytes;
        int i;

        for (i = 0; i < nfds; i++) {
                struct flow *flow = events[i].data.ptr;
                if (flow->fd == t->stop_efd) {
                        t->stop = 1;
                        break;
                }
                
                if (events[i].events & EPOLLIN) {
                        ssize_t to_read = flow->bytes_to_read;

                        if (to_read > opts->buffer_size)
                                to_read = opts->buffer_size;
                        
                        rcv_num_bytes = recvmmsg(flow->fd, buf, opts->burst_size, MSG_DONTWAIT, NULL);

                        if (rcv_num_bytes == -1) {
                                NP_PLOG_ERROR(cb, "read");
                                continue;
                        }

                        // echo back the packets -- immediately
                        // ECHO back what we recieved here
                        snd_num_bytes = sendmmsg(flow->fd, buf, rcv_num_bytes, MSG_DONTWAIT);

                        if (snd_num_bytes == -1) {
                                NP_PLOG_ERROR(cb, "write");
                                continue;
                        }

                        if (rcv_num_bytes > snd_num_bytes) {
                                printf("Could not echo back everything...\n");
                                continue;
                        }

                        t->transactions += rcv_num_bytes;
                        t->sent_transactions += snd_num_bytes;
                        flow->transactions += rcv_num_bytes;
                        flow->sent_transactions += snd_num_bytes;
                        flow->bytes_read += rcv_num_bytes * opts->packet_size;

                        events[i].events = EPOLLIN | EPOLLET | EPOLLONESHOT;
                        epoll_ctl_or_die(epfd, EPOLL_CTL_MOD, flow->fd, &events[i], cb);
                }
        }
}

static struct flow* epoll_add_udp_flow(int epollfd, int fd, uint32_t events, struct options *opts, struct callbacks *cb)
{
        struct epoll_event ev;
        struct flow *flow;

        if (opts->debug) {
                set_debug(fd, 1, cb);
        }
        set_nonblocking(fd, cb);
        if (opts->reuseaddr)
                set_reuseaddr(fd, 1, cb);
        flow = calloc(1, sizeof(struct flow));
        flow->fd = fd;
        flow->id = 1;
        flow->latency = numlist_create(cb);
        ev.events = events;
        ev.data.ptr = flow;
        epoll_ctl_or_die(epollfd, EPOLL_CTL_ADD, fd, &ev, cb);
        return flow;
}

static void run_server(struct thread *t)
{
        struct options *opts = t->opts;
        struct callbacks *cb = t->cb;
        struct addrinfo *ai = t->ai[0];
        struct epoll_event *events;
        int fd_listen, epfd;
        struct mmsghdr *buf;

        fd_listen = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd_listen == -1)
                NP_PLOG_FATAL(cb, "socket");
        set_reuseport(fd_listen, cb);
        set_reuseaddr(fd_listen, 1, cb);
        
        if (bind(fd_listen, ai->ai_addr, ai->ai_addrlen))
                NP_PLOG_FATAL(cb, "bind");
 
        epfd = epoll_create1(0);
        if (epfd == -1)
                NP_PLOG_FATAL(cb, "epoll_create1");
        epoll_add_or_die(epfd, t->stop_efd, EPOLLIN, cb);
        epoll_add_udp_flow(epfd, fd_listen, EPOLLIN | EPOLLET | EPOLLONESHOT, opts, cb);
        events = calloc(opts->maxevents, sizeof(struct epoll_event));
        buf = buf_alloc(opts, true);
        pthread_barrier_wait(t->ready);
        while (!t->stop) {
                int ms = opts->nonblocking ? 10 /* milliseconds */ : -1;
                int nfds = epoll_wait(epfd, events, opts->maxevents, ms);
                if (nfds == -1) {
                        if (errno == EINTR)
                                continue;
                        NP_PLOG_FATAL(cb, "epoll_wait");
                }
                server_events(t, epfd, events, nfds, fd_listen, buf);
        }
        free(buf);
        free(events);
        do_close(epfd);
}

static void *thread_start(void *arg)
{
        struct thread *t = arg;

        if (t->opts->client) {
                int i = 0;
                for (i = 0; i < t->num_hosts; i++) {
                        reset_port_udp(&t->ai[i], &(t->opts->host[i]), t->opts, 0, t->cb);
                }
                run_client(t);
        } else {
                struct host srv = {NULL,
                                   (char *)t->opts->control_port,
                                   (char *)t->opts->port};
                reset_port_udp(&t->ai[0], &srv, t->opts, AI_PASSIVE, t->cb);
                run_server(t);
        }
        return NULL;
}

static void report_latency(struct sample *samples, int start, int end,
                           struct options *opts, struct callbacks *cb)
{
        struct numlist *all = samples[start].latency;
        int i;

        if (!opts->client)
                return;

        for (i = start + 1; i <= end; i++)
                numlist_concat(all, samples[i].latency);

        PRINT(cb, "latency_min", "%f", numlist_min(all));
        PRINT(cb, "latency_max", "%f", numlist_max(all));
        PRINT(cb, "latency_mean", "%f", numlist_mean(all));
        PRINT(cb, "latency_stddev", "%f", numlist_stddev(all));

        for (i = 0; i <= 100; i++) {
                if (opts->percentiles.chosen[i]) {
                        char key[13];
                        sprintf(key, "latency_p%d", i);
                        PRINT(cb, key, "%f", numlist_percentile(all, i));
                }
        }
}

static void report_stats(struct thread *tinfo)
{
        struct sample *p, *samples;
        struct timespec *start_time;
        int num_samples, i, j, tid, flow_id, start_index, end_index;
        unsigned long start_total, sent_total, current_total, **per_flow;
        double duration, total_work, throughput, correlation_coefficient,
               sum_xy = 0, sum_xx = 0, sum_yy = 0;
        struct options *opts = tinfo[0].opts;
        struct callbacks *cb = tinfo[0].cb;

        num_samples = 0;
        current_total = 0;
        sent_total = 0;
        for (i = 0; i < opts->num_threads; i++) {
                for (p = tinfo[i].samples; p; p = p->next)
                        num_samples++;
                current_total += tinfo[i].transactions;
        }
        for (i = 0; i < opts->num_threads; i++) {
               sent_total += tinfo[i].sent_transactions;
        }

        PRINT(cb, "num_transactions", "%lu", current_total);
        PRINT(cb, "sent_transactions", "%lu", sent_total);
        if (num_samples == 0) {
                NP_LOG_WARN(cb, "no sample collected");
                return;
        }
        samples = calloc(num_samples, sizeof(samples[0]));
        if (!samples)
                NP_LOG_FATAL(cb, "calloc samples");
        j = 0;
        for (i = 0; i < opts->num_threads; i++)
                for (p = tinfo[i].samples; p; p = p->next)
                        samples[j++] = *p;
        qsort(samples, num_samples, sizeof(samples[0]), compare_samples);
        if (opts->all_samples) {
                print_samples(&opts->percentiles, samples, num_samples,
                              opts->all_samples, cb);
        }
        start_index = 0;
        end_index = num_samples - 1;
        PRINT(cb, "start_index", "%d", start_index);
        PRINT(cb, "end_index", "%d", end_index);
        PRINT(cb, "num_samples", "%d", num_samples);
        if (start_index >= end_index) {
                NP_LOG_WARN(cb, "insufficient number of samples");
                return;
        }
        start_time = &samples[start_index].timestamp;
        start_total = samples[start_index].transactions;
        current_total = start_total;
        per_flow = calloc(opts->num_threads, sizeof(unsigned long *));
        if (!per_flow)
                NP_LOG_FATAL(cb, "calloc per_flow");
        for (i = 0; i < opts->num_threads; i++) {
                int max_flow_id = 0;
                for (p = tinfo[i].samples; p; p = p->next) {
                        if (p->flow_id > max_flow_id)
                                max_flow_id = p->flow_id;
                }
                per_flow[i] = calloc(max_flow_id + 1, sizeof(unsigned long));
                if (!per_flow[i])
                        NP_LOG_FATAL(cb, "calloc per_flow[%d]", i);
        }
        tid = samples[start_index].tid;
        assert(tid >= 0 && tid < opts->num_threads);
        flow_id = samples[start_index].flow_id;
        per_flow[tid][flow_id] = start_total;
        for (j = start_index + 1; j <= end_index; j++) {
                tid = samples[j].tid;
                assert(tid >= 0 && tid < opts->num_threads);
                flow_id = samples[j].flow_id;
                current_total -= per_flow[tid][flow_id];
                per_flow[tid][flow_id] = samples[j].transactions;
                current_total += per_flow[tid][flow_id];
                duration = seconds_between(start_time, &samples[j].timestamp);
                total_work = current_total - start_total;
                sum_xy += duration * total_work;
                sum_xx += duration * duration;
                sum_yy += total_work * total_work;
        }
        throughput = total_work / duration;
        correlation_coefficient = sum_xy / sqrt(sum_xx * sum_yy);
        PRINT(cb, "throughput", "%.2f", throughput);
        PRINT(cb, "correlation_coefficient", "%.2f", correlation_coefficient);
        for (i = 0; i < opts->num_threads; i++)
                free(per_flow[i]);
        free(per_flow);
        PRINT(cb, "time_end", "%ld.%09ld", samples[num_samples-1].timestamp.tv_sec,
              samples[num_samples-1].timestamp.tv_nsec);
        report_latency(samples, start_index, end_index, opts, cb);
        free(samples);
}

int udp_flood(struct options *opts, struct callbacks *cb)
{
        return run_main_thread(opts, cb, thread_start, report_stats);
}
