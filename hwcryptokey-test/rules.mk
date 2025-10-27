# Copyright (C) 2022 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MANIFEST := $(LOCAL_DIR)/manifest.json

MODULE_SRCS += \
	$(LOCAL_DIR)/main.rs \

MODULE_CRATE_NAME := hwcryptokey_test

MODULE_LIBRARY_DEPS += \
	frameworks/native/libs/binder/trusty/rust \
	frameworks/native/libs/binder/trusty/rust/rpcbinder \
	trusty/user/app/sample/hwcryptohal/aidl/rust  \
	trusty/user/app/sample/hwcryptohal/common \
	trusty/user/base/lib/keymint-rust/boringssl \
	trusty/user/base/lib/keymint-rust/common \
	trusty/user/base/lib/openssl-rust \
	trusty/user/base/lib/service_manager/client \
	trusty/user/base/lib/trusty-std \
	$(call FIND_CRATE,log) \


ifeq (true,$(call TOBOOL,$(HWCRYPTO_EXCLUDE_SYMMETRIC_OPERATION_TESTS)))
MODULE_RUSTFLAGS += --cfg 'feature="exclude_symmetric_operation_tests"'

endif

MODULE_RUST_TESTS := true

include make/library.mk
