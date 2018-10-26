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

#ifndef NEPER_CONTROL_PLANE_H
#define NEPER_CONTROL_PLANE_H

struct addrinfo;
struct callbacks;
struct control_plane;
struct peer_control;
struct host;
struct options;
struct thread;

struct control_plane* control_plane_create(struct options *opts,
                                           struct callbacks *cb);
struct peer_control* peer_control_create(struct options *opts,
                                         struct callbacks *cb);

void control_plane_start(struct control_plane *cp, struct addrinfo **ai);
void control_plane_wait_until_done(struct control_plane *cp);
void control_plane_stop(struct control_plane *cp);
int control_plane_incidents(struct control_plane *cp);
void control_plane_destroy(struct control_plane *cp);

struct host* peer_control_start(struct peer_control *pc);
void peer_control_wait_for_signal(struct peer_control *pc);
void peer_control_wait_for_stats(struct peer_control *pc, struct thread *tinfo);
void peer_control_stop(struct peer_control *pc);
void peer_control_destroy(struct peer_control *pc);

#endif
