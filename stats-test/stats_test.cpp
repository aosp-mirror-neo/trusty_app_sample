/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define TLOG_LEVEL TLOG_LEVEL_DEBUG
#define TLOG_TAG "stats-test"

#include <inttypes.h>
#include <lk/macros.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <lib/tipc/tipc.h>
#include <lib/unittest/unittest.h>
#include <trusty/memref.h>
#include <trusty/sys/mman.h>
#include <trusty/time.h>
#include <trusty/uuid.h>
#include <trusty_log.h>
#include <interface/metrics/consumer.h>
#include <trusty_unittest.h>
#include <uapi/err.h>

static handle_t metrics_chan;

static int consumer_connect(handle_t* chan) {
    return tipc_connect(chan, METRICS_CONSUMER_PORT);
}

enum TrustyAtoms : int32_t {
    TrustyAppCrashed = 100072,
    TrustyError = 100145,
    TrustyStorageError = 100146
};

typedef struct {
} stats_test_t;

TEST_F_SETUP(stats_test) {
    int rc = consumer_connect(&metrics_chan);
    ASSERT_EQ(rc, 0);
test_abort:;
}

TEST_F_TEARDOWN(stats_test) {
    close(metrics_chan);
}

TEST_F(stats_test, atom_trusty_app_crashed) {
    int rc;
    struct metrics_req req;
    struct metrics_report_crash_req args;

   char test_uuid[37] = "5247d19b-cf09-4272-a450-3ef20dbefc14";

   memcpy(args.app_id, test_uuid, 37);

    req.cmd = METRICS_CMD_REPORT_CRASH;
    args.crash_reason = 0xdeafd00f;

    struct iovec iovs[] = {
            {
                    .iov_base = &req,
                    .iov_len = sizeof(req),
            },
            {
                    .iov_base = &args,
                    .iov_len = sizeof(args),
            },
    };
    struct ipc_msg msg = {
            .num_iov = countof(iovs),
            .iov = iovs,
    };

    int total_len = sizeof(req) + sizeof(args);
    rc = send_msg(metrics_chan, &msg);
    if (rc != (int)total_len) {
        TLOGE("failed (%d) to send storage event\n", rc);
    }
test_abort:;
}

TEST_F(stats_test, atom_second_app_crashed) {
    int rc;
    struct metrics_req req;
    struct metrics_report_crash_req args;

   char test_uuid[37] = "5247d19b-cf09-4272-a450-3ef20dbefc14";

   memcpy(args.app_id, test_uuid, 37);

    req.cmd = METRICS_CMD_REPORT_CRASH;
    args.crash_reason = 0xdeafd00f;

    struct iovec iovs[] = {
            {
                    .iov_base = &req,
                    .iov_len = sizeof(req),
            },
            {
                    .iov_base = &args,
                    .iov_len = sizeof(args),
            },
    };
    struct ipc_msg msg = {
            .num_iov = countof(iovs),
            .iov = iovs,
    };

    int total_len = sizeof(req) + sizeof(args);
    rc = send_msg(metrics_chan, &msg);
    if (rc != (int)total_len) {
        TLOGE("failed (%d) to send storage event\n", rc);
    }
test_abort:;
}

PORT_TEST(stats_test, "com.android.trusty.stats.test")
