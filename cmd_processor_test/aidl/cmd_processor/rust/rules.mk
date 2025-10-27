# Copyright (C) 2023 The Android Open Source Project
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

CMD_PROCESSOR_AIDL_DIR = device/generic/trusty/custom_vm/memshare_vm/aidl
MEM_BUFF_AIDL_DIR = device/generic/trusty/custom_vm/memshare_vm/aidl/android/trusty/membuf

MODULE_CRATE_NAME := android_trusty_cmdprocessor

MODULE_AIDL_LANGUAGE := rust

MODULE_AIDL_PACKAGE := android/trusty/cmdprocessor

MODULE_AIDL_INCLUDES := \
	-I $(CMD_PROCESSOR_AIDL_DIR) \
	-I $(MEM_BUFF_AIDL_DIR) \

MODULE_AIDL_RUST_DEPS += android_trusty_membuf

MODULE_LIBRARY_DEPS += \
	trusty/user/app/sample/cmd_processor_test/aidl/mem_buf/rust \

MODULE_AIDLS := \
    $(CMD_PROCESSOR_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/ICommandProcessor.aidl     \
    $(CMD_PROCESSOR_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/MemoryBufferReference.aidl \

include make/aidl.mk
