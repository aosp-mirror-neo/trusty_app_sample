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

#define TLOG_TAG "binder-test-handover"

#include <binder/ParcelFileDescriptor.h>
#include <binder/RpcServerTrusty.h>
#include <binder/RpcTransportTipcTrusty.h>
#include <com/android/trusty/binder/test/ITestService.h>
#include <lib/tipc/peer_id.h>
#include <lib/tipc/tipc.h>
#include <lib/tipc/tipc_srv.h>
#include <lk/err_ptr.h>
#include <trusty_log.h>
#include <uapi/err.h>
#include <uapi/trusty_peer_id.h>

using android::binder::Status;
using android::os::ParcelFileDescriptor;

using com::android::trusty::binder::test::ITestService;

int on_connect(const struct tipc_port* port,
               handle_t chan,
               const struct trusty_peer_id* peer,
               size_t peer_len,
               void** ctx_p) {
    TLOGD("New connection to HND_PORT. Channel: %d\n", chan);
    return NO_ERROR;
}

int on_message(const struct tipc_port* port, handle_t chan, void* ctx) {
    android::sp<ITestService>& srv =
            *reinterpret_cast<android::sp<ITestService>*>(
                    const_cast<void*>(port->priv));

    if (srv == nullptr) {
        TLOGE("on_message called before getting ITestService. Should be "
              "unreachable.");
        return ERR_BAD_STATE;
    }

    int rc = tipc_recv1(chan, 0, nullptr, 0);
    if (rc != NO_ERROR) {
        return rc;
    }

    TLOGD("Got message to HND_PORT (chan: %d); handing over.\n", chan);

    rc = dup(chan);
    if (rc < 0) {
        TLOGE("on_message failed (%d) to dup channel %d.\n", rc, chan);
        return ERR_BAD_STATE;
    }
    handle_t dup_chan = rc;

    auto fd = ParcelFileDescriptor(android::binder::unique_fd(dup_chan));
    auto status = srv->Handover(fd);
    if (!status.isOk()) {
        TLOGE("Handover failed: %s", status.toString8().c_str());
        return ERR_GENERIC;
    }

    /*
     * Server side of chan now belongs to the test service; return an error to
     * close our chan copy and remove it from the handle_set.
     */
    return ERR_CANCELLED;
}

int main(void) {
    TLOGD("Connecting to TestService\n");
    android::binder::unique_fd chan;

    int rc = connect(ITestService::PORT().c_str(), IPC_CONNECT_WAIT_FOR_PORT);
    if (rc < 0) {
        TLOGE("Connect to test service failed: %d\n", rc);
        return EXIT_FAILURE;
    }
    chan.reset(rc);

    android::sp<android::RpcSession> sess = android::RpcSession::make(
            android::RpcTransportCtxFactoryTipcTrusty::make());
    if (sess == nullptr) {
        TLOGE("Failed to start RpcSession.\n");
        return EXIT_FAILURE;
    }
    sess->setFileDescriptorTransportMode(
            android::RpcSession::FileDescriptorTransportMode::TRUSTY);

    android::status_t status = sess->setupPreconnectedClient(
            std::move(chan), []() { return android::binder::unique_fd(); });
    if (status != android::OK) {
        TLOGE("Failed to setupPreconnectedClient.\n");
        return EXIT_FAILURE;
    }

    android::sp<android::IBinder> root = sess->getRootObject();
    if (root == nullptr) {
        TLOGE("Failed to getRootObject.\n");
        return EXIT_FAILURE;
    }

    android::sp<ITestService> srv = ITestService::asInterface(root);
    if (srv == nullptr) {
        TLOGE("Failed to cast root object to ITestService.\n");
        return EXIT_FAILURE;
    }

    TLOGI("Starting service\n");

    tipc_hset* hset = tipc_hset_create();
    if (IS_ERR(hset)) {
        TLOGE("Failed to create handle set (%d)\n", PTR_ERR(hset));
        return EXIT_FAILURE;
    }

    const auto port_acl = tipc_port_acl{
            .flags = IPC_PORT_ALLOW_TA_CONNECT | IPC_PORT_ALLOW_NS_CONNECT,
    };
    const auto port = tipc_port{
            .name = ITestService::HND_PORT().c_str(),
            .msg_max_size = 256,
            .msg_queue_len = 1,
            .acl = &port_acl,
            .priv = &srv,
    };
    auto srv_ops = tipc_srv_ops{
            .on_connect_peer_id = on_connect,
            .on_message = on_message,
    };

    tipc_add_service(hset, &port, 1, 1, &srv_ops);
    return tipc_run_event_loop(hset);
}
