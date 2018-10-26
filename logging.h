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

#ifndef NEPER_LOGGING_H
#define NEPER_LOGGING_H

struct callbacks;

void logging_init(struct callbacks *);
void logging_exit(struct callbacks *);

#define PRINT(cb, key, value_fmt, args...) \
        (cb)->print((cb)->logger, key, value_fmt, ##args)
#define NP_LOG_FATAL(cb, fmt, args...) \
        (cb)->log_fatal((cb)->logger, __FILE__, __LINE__, __func__, fmt, ##args)
#define NP_LOG_ERROR(cb, fmt, args...) \
        (cb)->log_error((cb)->logger, __FILE__, __LINE__, __func__, fmt, ##args)
#define NP_LOG_WARN(cb, fmt, args...) \
        (cb)->log_warn((cb)->logger, __FILE__, __LINE__, __func__, fmt, ##args)
#define NP_LOG_INFO(cb, fmt, args...) \
        (cb)->log_info((cb)->logger, __FILE__, __LINE__, __func__, fmt, ##args)
#define NP_PLOG_FATAL(cb, fmt, args...) \
        NP_LOG_FATAL(cb, fmt ": %s", ##args, strerror(errno))
#define NP_PLOG_ERROR(cb, fmt, args...) \
        NP_LOG_ERROR(cb, fmt ": %s", ##args, strerror(errno))
#define CHECK(cb, cond, fmt, args...) \
        if (!(cond)) \
                NP_LOG_FATAL(cb, fmt, ##args)

#endif
