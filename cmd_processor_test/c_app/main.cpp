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
#include <iterator>
#include <vector>

#include <android/trusty/cmdprocessor/BnCommandProcessor.h>
#include <binder/ParcelFileDescriptor.h>
#include <binder/RpcServerTrusty.h>

#include <dmaimporterlib.h>
#include <memory_buffer_share.hpp>

using android::binder::Status;
using android::os::ParcelFileDescriptor;
using android::trusty::cmdprocessor::BnCommandProcessor;
using android::trusty::cmdprocessor::ICommandProcessor;
using android::trusty::cmdprocessor::MemoryBufferReference;
using std::vector;

#define TIPC_QUEUE_LEN 3
#define BUFFER_SIZE 4096

#define SHARED_BUFFER_SIZE 1024 * 1024

#define CMD_PROCESSOR_PORT \
    "android.trusty.cmdprocessor.ICommandProcessor/default"

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
        TLOGI("processCommand called\n");
        if (commandName == android::String16("print")) {
            if (memBufferRefs.size() > 0) {
                // We will use the first element on the cmdDataIn if present to
                // indicate how many bytes to print or default to 5
                size_t num_bytes_print = 5;
                if (cmdDataIn.size() > 0) {
                    num_bytes_print = cmdDataIn[0];
                }
                handle_t handle =
                        deserialize_token(memBufferRefs[0].token.token);
                TLOGI("Mapping handle: %x\n", handle);
                void* mapped_address =
                        mmap(0, SHARED_BUFFER_SIZE, PROT_READ | PROT_WRITE, 0,
                             handle, 0);
                if (mapped_address == MAP_FAILED) {
                    TLOGE("Couldn't map handle %x\n", handle);
                    return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE,
                                                     "Couldn't map address");
                } else {
                    TLOGI("Handle %x was mapped\n", handle);
                }
                uint8_t* mapped_data = (uint8_t*)mapped_address;
                for (size_t i = 0; i < num_bytes_print; i++) {
                    TLOGE("Received data[i]= %d\n", *mapped_data);
                    mapped_data++;
                }
                int res = munmap(mapped_address, SHARED_BUFFER_SIZE);
                if (res != 0) {
                    TLOGE("munmap %p failed: %d\n", mapped_address, res);
                }
            } else {
                TLOGE("Didn't receive memory buffers to print\n");
                return Status::fromExceptionCode(
                        Status::EX_ILLEGAL_ARGUMENT,
                        "Didn't receive memory buffers to print");
            }
        } else if (commandName == android::String16("increment")) {
            if (memBufferRefs.size() > 0) {
                handle_t handle =
                        deserialize_token(memBufferRefs[0].token.token);
                TLOGI("Mapping handle: %x\n", handle);
                void* mapped_address =
                        mmap(0, SHARED_BUFFER_SIZE, PROT_READ | PROT_WRITE, 0,
                             handle, 0);
                if (mapped_address == NULL) {
                    TLOGE("Couldn't map handle %x\n", handle);
                    return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE,
                                                     "Couldn't map address");
                }
                uint8_t* mapped_data = (uint8_t*)mapped_address;
                *mapped_data += 1;
                int res = munmap(mapped_address, SHARED_BUFFER_SIZE);
                if (res != 0) {
                    TLOGE("munmap %p failed: %d\n", mapped_address, res);
                }
            } else {
                TLOGE("Didn't receive memory buffers to increment\n");
                return Status::fromExceptionCode(
                        Status::EX_ILLEGAL_ARGUMENT,
                        "Didn't receive memory buffers to increment");
            }

        } else if (commandName == android::String16("ping")) {
            TLOGI("ping!!!!!\n");
        } else {
            TLOGE("Unknown command received\n");
            return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT,
                                             "Unknown command received");
        }
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
            create_memory_buffer_share(mem_share_rpc_srv);
    if (mem_share_srv == nullptr) {
        return EXIT_FAILURE;
    }

    auto rc = tipc_run_event_loop(hset);
    TLOGE("Test c app stopped executing\n");
    return rc;
}
