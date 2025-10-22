# Copyright (C) 2024 The Android Open Source Project
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
	$(LOCAL_DIR)/lib.rs \

MODULE_CRATE_NAME := hwcryptohalserver

MODULE_LIBRARY_DEPS += \
	frameworks/native/libs/binder/trusty/rust \
	trusty/user/app/sample/hwcryptohal/aidl/rust  \
	trusty/user/app/sample/hwcryptohal/common  \
	trusty/user/base/interface/shared_secret/aidl \
	trusty/user/app/sample/hwcryptohal/server/interfaces \
	trusty/user/app/sample/hwcryptohal/server/platform \
	trusty/user/base/lib/keymint-rust/common \
	$(call FIND_CRATE,log) \
	$(call FIND_CRATE,static_assertions) \
	trusty/user/base/lib/trusty-log \

ifeq (true,$(call TOBOOL,$(HWCRYPTO_VM_CRATE_SUPPORT)))
MODULE_LIBRARY_DEPS += $(call FIND_CRATE,vm-memory)

endif

MODULE_RUST_TESTS := true

MODULE_RUST_USE_CLIPPY := true

ifeq (true,$(call TOBOOL,$(HWCRYPTO_VM_CRATE_SUPPORT)))
MODULE_RUSTFLAGS += --cfg 'feature="use_vm_memory_crate"'

endif

include make/library.mk
