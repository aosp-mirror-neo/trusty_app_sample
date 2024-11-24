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

HWCRYPTO_AIDL_DIR = hardware/interfaces/staging/security/see/hwcrypto/aidl

MODULE_CRATE_NAME := android_hardware_security_see

MODULE_AIDL_LANGUAGE := rust

MODULE_AIDL_PACKAGE := android/hardware/security/see/hwcrypto

MODULE_AIDL_INCLUDES := \
	-I $(HWCRYPTO_AIDL_DIR) \

MODULE_AIDLS := \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/CryptoOperation.aidl                        \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/CryptoOperationErrorAdditionalInfo.aidl     \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/CryptoOperationResult.aidl                  \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/CryptoOperationSet.aidl                     \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/ICryptoOperationContext.aidl                \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/IHwCryptoKey.aidl                           \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/IHwCryptoOperations.aidl                    \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/IOpaqueKey.aidl                             \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/KeyPolicy.aidl                              \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/MemoryBufferParameter.aidl                  \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/OperationParameters.aidl                    \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/PatternParameters.aidl                      \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/AesCipherMode.aidl                    \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/AesGcmMode.aidl                       \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/AesKey.aidl                           \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/CipherModeParameters.aidl             \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/ExplicitKeyMaterial.aidl              \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/HalErrorCode.aidl                     \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/HmacOperationParameters.aidl          \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/HmacKey.aidl          \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/KeyLifetime.aidl                      \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/KeyPermissions.aidl                   \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/KeyType.aidl                          \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/KeyUse.aidl                           \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/MemoryBufferReference.aidl            \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/OpaqueKeyToken.aidl                   \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/OperationData.aidl                    \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/OperationType.aidl                    \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/ProtectionId.aidl                     \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/SymmetricAuthCryptoParameters.aidl    \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/SymmetricAuthOperationParameters.aidl \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/SymmetricCryptoParameters.aidl        \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/SymmetricOperation.aidl               \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/SymmetricOperationParameters.aidl     \
    $(HWCRYPTO_AIDL_DIR)/$(MODULE_AIDL_PACKAGE)/types/Void.aidl                             \

include make/aidl.mk
