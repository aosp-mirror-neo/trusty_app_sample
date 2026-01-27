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
#include <android/trusty/membuf/BnMemoryBufferContext.h>
#include <android/trusty/membuf/BnMemoryBufferShareVm.h>
#include <binder/ParcelFileDescriptor.h>
#include <binder/RpcServerTrusty.h>

#include <dmaimporterlib.h>

using android::binder::Status;
using android::os::ParcelFileDescriptor;
using android::trusty::cmdprocessor::BnCommandProcessor;
using android::trusty::cmdprocessor::ICommandProcessor;
using android::trusty::cmdprocessor::MemoryBufferReference;
using android::trusty::membuf::BnMemoryBufferContext;
using android::trusty::membuf::BnMemoryBufferShareVm;
using android::trusty::membuf::IMemoryBufferContext;
using android::trusty::membuf::IMemoryBufferShareVm;
using android::trusty::membuf::MemoryBufferToken;
using android::trusty::membuf::ShareMemoryBufferResult;
using std::vector;

#define TIPC_QUEUE_LEN 3
#define BUFFER_SIZE 4096

#define SHARED_BUFFER_SIZE 1024 * 1024

#define CMD_PROCESSOR_PORT \
    "android.trusty.cmdprocessor.ICommandProcessor/default"
#define MEM_SHARE_PORT "android.trusty.membuf.IMemoryBufferShareVm/default"

handle_t deserialize_token(const vector<uint8_t>& serialized_token) {
    handle_t handle = 0;

    for (auto element = serialized_token.rbegin();
         element != serialized_token.rend(); ++element) {
        handle = handle << 8;
        handle |= *element;
    }
    return handle;
}

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

class MemoryBufferContext : public BnMemoryBufferContext {
public:
    static android::sp<MemoryBufferContext> Make(handle_t handle,
                                                 uint64_t ipa) {
        auto self = android::sp<MemoryBufferContext>::make(handle, ipa);
        return self;
    }

    MemoryBufferContext(handle_t handle, uint64_t ipa)
            : handle_(handle), destroyed_(false), ipa_(ipa) {}

    ~MemoryBufferContext() {
        if (!destroyed_) {
            TLOGE("MemoryBufferContext object destroyed before calling release\n");
            int res = release_dma_object(&handle_, ipa_);
            if (res != NO_ERROR) {
                TLOGE("couldn't release handle %x with ipa: 0x%lx\n", handle_,
                      ipa_);
            }
            handle_ = -1;
            destroyed_ = true;
        }
    }

    Status getPortableToken(MemoryBufferToken* aidl_return) override {
        TLOGI("In getPortableToken\n");
        if (aidl_return == nullptr) {
            TLOGE("Received a null MemoryBufferToken\n");
            return Status::fromExceptionCode(
                    Status::EX_NULL_POINTER,
                    "Received a null MemoryBufferToken");
        }
        if (destroyed_) {
            // object is no longer usable
            TLOGE("MemoryBufferToken has already been destroyed\n");
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "MemoryBufferToken has already been destroyed");
        }
        // TODO: check if we should provide tampering protection to the token
        vector<uint8_t> serialized_token;
        TLOGI("serializing handle %x\n", handle_);
        handle_t token = handle_;
        for (size_t i = 0; i < sizeof(handle_t); i++) {
            uint8_t element = token & 0xff;
            serialized_token.push_back(element);
            token = token >> 8;
        }
        aidl_return->token = std::move(serialized_token);
        return Status::ok();
    }

    Status releaseMemoryBufferContext(int32_t* aidl_return) override {
        if (destroyed_) {
            // object is no longer usable
            TLOGE("MemoryBufferToken has already been destroyed\n");
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "MemoryBufferToken has already been destroyed");
        }
        destroyed_ = true;
        int res = release_dma_object(&handle_, ipa_);
        if (res != NO_ERROR) {
            TLOGE("couldn't release handle %x\n", handle_);
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Couldn't release MemoryBufferToken handle");
        } else {
            TLOGI("Released handle %x with ipa: 0x%lx\n", handle_, ipa_);
            handle_ = -1;
        }
        if (aidl_return != nullptr) {
            // TODO: change returned value
            *aidl_return = res;
        }
        return Status::ok();
    }

private:
    handle_t handle_;
    bool destroyed_;
    uint64_t ipa_;
};

class MemoryBufferShare : public BnMemoryBufferShareVm {
public:
    static android::sp<MemoryBufferShare> Make(
            android::sp<android::RpcServerTrusty> srv) {
        auto self = android::sp<MemoryBufferShare>::make();
        srv->setRootObject(self);
        return self;
    }

    MemoryBufferShare() {}

    Status shareMemoryBuffer(int64_t ipa,
                             int32_t sizeBytes,
                             ShareMemoryBufferResult* aidl_return) override {
        TLOGI("In shareMemoryBuffer\n");
        if (aidl_return == nullptr) {
            TLOGE("reReceived a null ShareMemoryBufferResult\n");
            return Status::fromExceptionCode(
                    Status::EX_NULL_POINTER,
                    "Received a null ShareMemoryBufferResult");
        }
        handle_t handle;
        int rc = create_dma_object(ipa, sizeBytes, &handle);
        if (rc < 0) {
            TLOGE("Couldn't get memory handle from ipa: %d\n", rc);
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Couldn't get memory handle from ipa");
        }
        android::sp<MemoryBufferContext> mem_buffer_ctx =
                MemoryBufferContext::Make(handle, ipa);
        aidl_return->context = mem_buffer_ctx;
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
