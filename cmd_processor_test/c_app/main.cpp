#define TLOG_TAG "test-c-app"

#include <inttypes.h>
#include <lib/tipc/peer_id.h>
#include <lib/tipc/tipc.h>
#include <lib/tipc/tipc_srv.h>
#include <lk/err_ptr.h>
#include <stdio.h>
#include <sys/mman.h>
#include <trusty/sys/mman.h>
#include <trusty_log.h>
#include <uapi/mm.h>
#include <vector>

#include <binder/ParcelFileDescriptor.h>
#include <binder/RpcServerTrusty.h>

#include <android/trusty/cmdprocessor/BnCommandProcessor.h>
#include <android/trusty/membuf/BnMemoryBufferShare.h>

using android::binder::Status;
using android::os::ParcelFileDescriptor;
using android::trusty::cmdprocessor::BnCommandProcessor;
using android::trusty::cmdprocessor::ICommandProcessor;
using android::trusty::cmdprocessor::MemoryBufferReference;
using android::trusty::membuf::BnMemoryBufferShare;
using android::trusty::membuf::IMemoryBufferShare;
using android::trusty::membuf::ShareMemoryBufferResult;
using std::vector;

#define TIPC_QUEUE_LEN 3
#define BUFFER_SIZE 4096

#define CMD_PROCESSOR_PORT \
    "android.trusty.cmdprocessor.ICommandProcessor/default"
#define MEM_SHARE_PORT "android.trusty.membuf.IMemoryBufferShare/default"

class CommandProcessor : public BnCommandProcessor {
public:
    static android::sp<CommandProcessor> Make(
            android::sp<android::RpcServerTrusty> srv) {
        auto self = android::sp<CommandProcessor>::make();
        srv->setRootObject(self);
        return self;
    }

    CommandProcessor() {}

    Status processCommand(const android::String16& commandName,
                          const vector<MemoryBufferReference>& memBufferRefs,
                          const vector<uint8_t>& cmdDataIn,
                          vector<uint8_t>* cmdDataOut) override {
        return Status::ok();
    }
};

class MemoryBufferShare : public BnMemoryBufferShare {
public:
    static android::sp<MemoryBufferShare> Make(
            android::sp<android::RpcServerTrusty> srv) {
        auto self = android::sp<MemoryBufferShare>::make();
        srv->setRootObject(self);
        return self;
    }

    MemoryBufferShare() {}

    Status shareMemoryBuffer(const ParcelFileDescriptor& fd,
                             int32_t sizeBytes,
                             ShareMemoryBufferResult* _aidl_return) override {
        return Status::ok();
    }
};

int main(void) {
    TLOGI("Starting test c app\n");

    tipc_hset* hset = tipc_hset_create();
    if (IS_ERR(hset)) {
        TLOGE("Failed to create handle set (%d)\n", PTR_ERR(hset));
        return EXIT_FAILURE;
    }

    const auto port_acl = android::RpcServerTrusty::PortAcl{
            .flags = IPC_PORT_ALLOW_TA_CONNECT | IPC_PORT_ALLOW_NS_CONNECT,
    };

    // message size needs to be large enough to cover all messages sent by the
    // client
    constexpr size_t max_msg_size = BUFFER_SIZE;

    auto cmd_process_rpc_srv = android::RpcServerTrusty::make(
            hset, CMD_PROCESSOR_PORT,
            std::make_shared<const android::RpcServerTrusty::PortAcl>(port_acl),
            max_msg_size, TIPC_QUEUE_LEN);

    if (cmd_process_rpc_srv == nullptr) {
        return EXIT_FAILURE;
    }

    android::sp<CommandProcessor> cmd_process_srv =
            CommandProcessor::Make(cmd_process_rpc_srv);
    if (cmd_process_srv == nullptr) {
        return EXIT_FAILURE;
    }

    auto mem_share_rpc_srv = android::RpcServerTrusty::make(
            hset, MEM_SHARE_PORT,
            std::make_shared<const android::RpcServerTrusty::PortAcl>(port_acl),
            max_msg_size, TIPC_QUEUE_LEN);

    if (mem_share_rpc_srv == nullptr) {
        return EXIT_FAILURE;
    }

    android::sp<MemoryBufferShare> mem_share_srv =
            MemoryBufferShare::Make(mem_share_rpc_srv);
    if (mem_share_srv == nullptr) {
        return EXIT_FAILURE;
    }

    auto rc = tipc_run_event_loop(hset);
    TLOGE("Test c app stopped executing\n");
    return rc;
}