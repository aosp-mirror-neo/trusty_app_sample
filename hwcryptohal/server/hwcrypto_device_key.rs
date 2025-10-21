/*
 * Copyright (C) 2024 The Android Open Source Project
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

//! Implementation of the `IHwCryptoKey` AIDL interface. It can be use to generate and
//! retrieve device specific keys.

use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
    types::{
        ExplicitKeyMaterial::ExplicitKeyMaterial, KeyLifetime::KeyLifetime, KeyType::KeyType,
        KeyUse::KeyUse, OpaqueKeyToken::OpaqueKeyToken,
    },
    IHwCryptoKey::{
        BnHwCryptoKey, DerivedKey::DerivedKey, DerivedKeyParameters::DerivedKeyParameters,
        DerivedKeyPolicy::DerivedKeyPolicy, DeviceKeyId::DeviceKeyId,
        DiceBoundDerivationKey::DiceBoundDerivationKey, DiceBoundKeyResult::DiceBoundKeyResult,
        DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult, IHwCryptoKey, KeySlot::KeySlot,
    },
    IHwCryptoOperations::IHwCryptoOperations,
    IOpaqueKey::IOpaqueKey,
    KeyPolicy::KeyPolicy,
};
use android_hardware_security_see_hwcrypto::binder;
use ciborium::Value;
use coset::{AsCborValue, CborSerializable, CoseError};
use hwcryptohal_common::{cose_enum_gen, err::HwCryptoError, hwcrypto_err};
use hwcryptohalinterfaces::{ClientIdentification, ClientPolicyCheck, DeviceKeys};
use hwcryptohalplatform::DeviceKeysImpl;
use kmr_common::crypto::KeyMaterial;

use crate::helpers;
use crate::hwcrypto_operations::HwCryptoOperations;
use crate::opaque_key::{self, DerivationContext, HkdfOperationType, OpaqueKey};
use crate::service_encryption_key::{
    self, EncryptedContent, EncryptionHeader, EncryptionHeaderKey,
};
use hwcryptohalplatform::ClientIdentificationImpl;

const DEVICE_KEY_CTX: &[u8] = b"device_key_derivation_contextKEK";

// enum used for serializing the `ClientPolicyWrapper`
// ClientPolicyWrapper = {
//     -65680 : bstr                        ; ClientPolicy
//     -65681 : bstr                        ; DeviceKeyPolicy
// }
cose_enum_gen! {
    enum ClientPolicyWrapperCoseLabels {
        ClientPolicy = -65680,
        DeviceKeyPolicy = -65681,
    }
}

// Object containing the Client policy and device key version. It will encrypt and decrypt them when
// interacting with the client. The current policy is based on the trusty version retrievable from
// HwKey and the uuid of the caller. Dice will be added once we have support for it. The device key
// version is used to retrieve a unique versioned key tied to the HwCrypto server.
// `ClientPolicyWrapper` encryption is similar to what KeyMint uses to wrap
// keys. While the stable policy returned by the `ClientPolicyWrapper` only includes the client
// policy, the generation of the derivation key consumes both this stable policy and the device key
// version.
struct ClientPolicyWrapper {
    client_policy: Vec<u8>,
    device_key_policy: Vec<u8>,
    header: Option<EncryptionHeader>,
}

impl ClientPolicyWrapper {
    // decrypts and returns a new `ClientPolicyWrapper`
    fn from_encrypted_slice(encrypted_wrapped_policy: &[u8]) -> Result<Self, HwCryptoError> {
        let (wrapped_policy_header, decrypted_data) =
            EncryptionHeader::decrypt_content_service_encryption_key(
                encrypted_wrapped_policy,
                EncryptionHeaderKey::KeyGenerationContext(DEVICE_KEY_CTX),
                EncryptedContent::ClientPolicy,
            )?;

        let mut wrapped_policy =
            ClientPolicyWrapper::from_cbor_value(Value::from_slice(&decrypted_data[..])?)?;
        wrapped_policy.header = Some(wrapped_policy_header);
        Ok(wrapped_policy)
    }

    // returns the current version of the platform device key service
    fn get_device_key_service_current_version() -> Result<Vec<u8>, HwCryptoError> {
        service_encryption_key::get_service_current_version()
    }

    // returns a new `ClientPolicyWrapper` with the version set to the current client version
    fn new_current(client_id: &[u8]) -> Result<Self, HwCryptoError> {
        let header = Some(EncryptionHeader::generate(EncryptedContent::ClientPolicy)?);
        let device_key_policy = Self::get_device_key_service_current_version()?;
        let client_policy = ClientIdentificationImpl::get_client_current_policy(client_id)?;
        Ok(ClientPolicyWrapper { client_policy, device_key_policy, header })
    }

    // consumes a `ClientPolicyWrapper` and returns it encrypted
    fn encrypt(mut self) -> Result<Vec<u8>, HwCryptoError> {
        let header = self.header.take().ok_or(hwcrypto_err!(BAD_PARAMETER, "no header found"))?;
        header.encrypt_content_service_encryption_key(
            EncryptionHeaderKey::KeyGenerationContext(DEVICE_KEY_CTX),
            self,
        )
    }

    // returns both the client policy and the device key version contained by the
    // `ClientPolicyWrapper`
    fn into_client_and_device_key_policies(self) -> Result<(Vec<u8>, Vec<u8>), HwCryptoError> {
        Ok((self.client_policy, self.device_key_policy))
    }
}

impl AsCborValue for ClientPolicyWrapper {
    fn to_cbor_value(self) -> Result<Value, CoseError> {
        let mut cbor_map = Vec::<(Value, Value)>::new();
        cbor_map.try_reserve(2).map_err(|_| CoseError::EncodeFailed)?;

        let key = Value::Integer((ClientPolicyWrapperCoseLabels::ClientPolicy as i64).into());
        let value = Value::Bytes(self.client_policy);
        cbor_map.push((key, value));

        let key = Value::Integer((ClientPolicyWrapperCoseLabels::DeviceKeyPolicy as i64).into());
        let value = Value::Bytes(self.device_key_policy);
        cbor_map.push((key, value));

        Ok(Value::Map(cbor_map))
    }

    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let wrapped_policy = value.into_map().map_err(|_| CoseError::ExtraneousData)?;
        let mut client_policy: Option<Vec<u8>> = None;
        let mut device_key_policy: Option<Vec<u8>> = None;
        for (map_key, map_val) in wrapped_policy {
            match map_key {
                Value::Integer(key) => {
                    match key.try_into().map_err(|_| {
                        CoseError::UnexpectedItem(
                            "value not matching enum",
                            "ClientPolicyWrapperCoseLabels",
                        )
                    })? {
                        ClientPolicyWrapperCoseLabels::ClientPolicy => {
                            client_policy =
                                Some(map_val.into_bytes().map_err(|_| {
                                    CoseError::UnexpectedItem("other type", "Bytes")
                                })?);
                        }
                        ClientPolicyWrapperCoseLabels::DeviceKeyPolicy => {
                            let parsed_version = map_val
                                .into_bytes()
                                .map_err(|_| CoseError::UnexpectedItem("other type", "Bytes"))?;
                            device_key_policy = Some(parsed_version);
                        }
                    }
                }
                _ => return Err(CoseError::ExtraneousData),
            }
        }
        let client_policy = client_policy.ok_or(CoseError::EncodeFailed)?;
        let device_key_policy = device_key_policy.ok_or(CoseError::EncodeFailed)?;
        // Header travels in the clear, the decoded section only contains the encrypted fields
        Ok(ClientPolicyWrapper { client_policy, device_key_policy, header: None })
    }
}

/// The `IHwCryptoKey` implementation.
#[derive(Debug)]
pub struct HwCryptoKey {
    pub(crate) client_id: Vec<u8>,
}

impl binder::Interface for HwCryptoKey {}

impl HwCryptoKey {
    pub fn new_binder(client_id: Vec<u8>) -> binder::Strong<dyn IHwCryptoKey> {
        let hwcrypto_device_key = HwCryptoKey { client_id };
        BnHwCryptoKey::new_binder(hwcrypto_device_key, binder::BinderFeatures::default())
    }

    // check_client_policy_owner shall only be false for creating internal keys that can be used
    // to seal content bounded to another party DICE policy
    pub(crate) fn derive_dice_policy_bound_key(
        &self,
        derivation_key: &DiceBoundDerivationKey,
        client_policy_for_versioned_key: &[u8],
        check_client_policy_owner: bool,
    ) -> Result<DiceBoundKeyResult, HwCryptoError> {
        // Verifying provided DICE policy
        // The policy that the client stores has 2 components: A dice policy that we get from
        // auth-manager (caller_client_policy) and a second policy that the platform implementation
        // of the DeviceKeys traits uses to retrieve a versioned device bound key
        // (device_key_policy).
        let (caller_client_policy, device_key_policy) =
            ClientPolicyWrapper::from_encrypted_slice(client_policy_for_versioned_key)?
                .into_client_and_device_key_policies()?;
        let ClientPolicyCheck { policy_matches, policy_is_current } =
            ClientIdentificationImpl::check_client_policy(
                self.client_id.as_slice(),
                caller_client_policy.as_slice(),
            )?;
        if check_client_policy_owner && !policy_matches {
            return Err(hwcrypto_err!(BAD_PARAMETER, "client identity mismatch"));
        }

        // The returned key will only be used for derivation, so fixing tis type to HMAC_SHA256
        let key_type = KeyType::HMAC_SHA256;
        let key_size = opaque_key::get_key_size_in_bytes(&key_type)?;

        let mut policy = KeyPolicy {
            usage: KeyUse::DERIVE,
            keyLifetime: KeyLifetime::HARDWARE,
            keyPermissions: Vec::new(),
            keyType: key_type,
            keyManagementKey: false,
        };

        match derivation_key {
            DiceBoundDerivationKey::KeyId(key_id) => {
                if DeviceKeyId::DEVICE_BOUND_KEY != *key_id {
                    return Err(hwcrypto_err!(UNSUPPORTED, "unknown key id {:?}", key_id));
                }
                let mut op_context =
                    DerivationContext::new(HkdfOperationType::DiceBoundDerivation)?;
                // Using the decrypted (stable) DICE policy for context, so keys derived with the
                // same version will match
                op_context.add_owned_binary_string(caller_client_policy)?;
                let concat_context = op_context.create_key_derivation_context()?;
                let derived_key = DeviceKeysImpl::derive_caller_unique_key(
                    concat_context.as_slice(),
                    device_key_policy.as_slice(),
                    key_size,
                )?;

                // Create a new opaque key from the generated key material
                let km = opaque_key::generate_key_material(&policy.keyType, Some(derived_key))?;
                let key = opaque_key::OpaqueKey::new_with_exportable_key(
                    &policy,
                    km,
                    self.client_id.as_slice(),
                )
                .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "failed to create key {:?}", e))?;
                Ok(DiceBoundKeyResult {
                    diceBoundKey: Some(key),
                    dicePolicyWasCurrent: policy_is_current,
                })
            }
            DiceBoundDerivationKey::OpaqueKey(opaque_key) => {
                let derivation_key: OpaqueKey = opaque_key
                    .as_ref()
                    .ok_or(hwcrypto_err!(BAD_PARAMETER, "derivation key not provided"))?
                    .try_into()?;
                // Getting derivation key policy
                let derivation_key_policy = derivation_key.getKeyPolicy().map_err(|e| {
                    hwcrypto_err!(GENERIC_ERROR, "couldn't get derivation key policy {:?}", e)
                })?;
                // Lifetime of the derived key is inherited from the derivation key
                policy.keyLifetime = derivation_key_policy.keyLifetime;
                let key = derivation_key
                    .derive_dice_bound_key(caller_client_policy, &policy, self.client_id.as_slice())
                    .map_err(|e| {
                        hwcrypto_err!(
                            GENERIC_ERROR,
                            "couldn't derive opaque dice bound key {:?}",
                            e
                        )
                    })?;
                Ok(DiceBoundKeyResult {
                    diceBoundKey: Some(key),
                    dicePolicyWasCurrent: policy_is_current,
                })
            }
        }
    }

    fn check_caller_can_access_keyslot(&self, keyslot: KeySlot) -> Result<(), HwCryptoError> {
        if ClientIdentificationImpl::client_can_access_keyslot(self.client_id.as_slice(), keyslot)?
        {
            Ok(())
        } else {
            Err(hwcrypto_err!(UNAUTHORIZED, "caller do not have permission to access this key"))
        }
    }
}

impl IHwCryptoKey for HwCryptoKey {
    fn deriveCurrentDicePolicyBoundKey(
        &self,
        derivation_key: &DiceBoundDerivationKey,
    ) -> binder::Result<DiceCurrentBoundKeyResult> {
        let client_policy =
            ClientPolicyWrapper::new_current(self.client_id.as_slice())?.encrypt()?;
        let derived_key_result =
            self.derive_dice_policy_bound_key(derivation_key, &client_policy, true)?;
        let DiceBoundKeyResult { diceBoundKey: key, dicePolicyWasCurrent: policy_current } =
            derived_key_result;
        if !policy_current {
            return Err(binder::Status::new_exception_str(
                binder::ExceptionCode::UNSUPPORTED_OPERATION,
                Some("generated a policy that was not the latest"),
            ));
        }
        Ok(DiceCurrentBoundKeyResult { diceBoundKey: key, dicePolicyForKeyVersion: client_policy })
    }

    fn deriveDicePolicyBoundKey(
        &self,
        derivation_key: &DiceBoundDerivationKey,
        client_policy_for_versioned_key: &[u8],
    ) -> binder::Result<DiceBoundKeyResult> {
        Ok(self.derive_dice_policy_bound_key(
            derivation_key,
            client_policy_for_versioned_key,
            true,
        )?)
    }

    fn getCurrentDicePolicy(&self) -> binder::Result<Vec<u8>> {
        Ok(ClientPolicyWrapper::new_current(self.client_id.as_slice())?.encrypt()?)
    }

    fn keyTokenImport(
        &self,
        key_token: &OpaqueKeyToken,
        sealing_client_policy: &[u8],
    ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
        // We derive a normal DICE bound key. This will check that the policy matches
        // our DICE chain.
        let DiceBoundKeyResult { diceBoundKey: key, dicePolicyWasCurrent: _ } = self
            .deriveDicePolicyBoundKey(
                &DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY),
                sealing_client_policy,
            )?;
        let key = key.ok_or(binder::Status::new_exception_str(
            binder::ExceptionCode::UNSUPPORTED_OPERATION,
            Some("shouldn't happen, previous operation succeeded"),
        ))?;
        let sealing_key: OpaqueKey = (&key).try_into().map_err(|_| {
            binder::Status::new_exception_str(
                binder::ExceptionCode::UNSUPPORTED_OPERATION,
                Some("shouldn't happen, opaque key was local"),
            )
        })?;

        Ok(opaque_key::OpaqueKey::import_token(
            key_token.keyToken.as_slice(),
            sealing_key,
            self.client_id.as_slice(),
        )?
        .into())
    }

    fn deriveKey(&self, parameters: &DerivedKeyParameters) -> binder::Result<DerivedKey> {
        if let DerivedKeyPolicy::ClearKeyPolicy(policy) = &parameters.keyPolicy {
            if policy.keySizeBytes <= 0 {
                return Err(binder::Status::new_exception_str(
                    binder::ExceptionCode::UNSUPPORTED_OPERATION,
                    Some("we do not support keys of length less or equal to 0"),
                ));
            }
        }

        let derivation_key: OpaqueKey = parameters
            .derivationKey
            .as_ref()
            .ok_or(binder::Status::new_exception_str(
                binder::ExceptionCode::UNSUPPORTED_OPERATION,
                Some("didn't receive a derivation key"),
            ))?
            .try_into()?;

        match &parameters.keyPolicy {
            DerivedKeyPolicy::ClearKeyPolicy(clear_policy) => {
                // Adding key size to the context as well for a similar reason as to add the key
                // policy to the context.
                let key_size = clear_policy.keySizeBytes.try_into().map_err(|_| {
                    binder::Status::new_exception_str(
                        binder::ExceptionCode::UNSUPPORTED_OPERATION,
                        Some("shouldn't happen, we checked that keySize was positive"),
                    )
                })?;

                let derived_key = derivation_key
                    .derive_clear_key_material(parameters.context.as_slice(), key_size)?;
                Ok(DerivedKey::ExplicitKey(derived_key))
            }
            DerivedKeyPolicy::OpaqueKey(key_policy) => {
                let derived_key = derivation_key.derive_opaque_key(
                    key_policy,
                    parameters.context.as_slice(),
                    self.client_id.as_slice(),
                )?;
                Ok(DerivedKey::Opaque(Some(derived_key)))
            }
        }
    }

    fn getHwCryptoOperations(&self) -> binder::Result<binder::Strong<dyn IHwCryptoOperations>> {
        Ok(HwCryptoOperations::new_binder())
    }

    fn importClearKey(
        &self,
        key_to_be_imported: &ExplicitKeyMaterial,
        new_key_policy: &KeyPolicy,
    ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
        let key_material = helpers::aidl_explicit_key_to_rust_key_material(key_to_be_imported)?;
        OpaqueKey::import_key_material(new_key_policy, key_material, self.client_id.as_slice())
    }

    fn getKeyslotData(&self, keyslot: KeySlot) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
        self.check_caller_can_access_keyslot(keyslot)?;
        match keyslot {
            KeySlot::KEYMINT_SHARED_HMAC_KEY => {
                let policy = KeyPolicy {
                    usage: KeyUse::SIGN,
                    keyLifetime: KeyLifetime::HARDWARE,
                    keyPermissions: Vec::new(),
                    keyType: KeyType::HMAC_SHA256,
                    keyManagementKey: false,
                };
                let hmac_key = DeviceKeysImpl::get_keymint_shared_hmac_key(&policy)?.0;
                OpaqueKey::new_with_unexportable_key(
                    &policy,
                    KeyMaterial::Hmac(hmac_key),
                    self.client_id.as_slice(),
                )
            }
            _ => Err(binder::Status::new_exception_str(
                binder::ExceptionCode::UNSUPPORTED_OPERATION,
                Some("Unknown key slot requested"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::AesKey::AesKey;
    use test::{assert_ok, expect};

    use crate::tests::{connection_info, connection_info_second_identity};

    #[test]
    fn key_token_import_wrong_policy() {
        let hw_key = HwCryptoKey::new_binder(connection_info());

        let aes_key_material: ExplicitKeyMaterial =
            ExplicitKeyMaterial::Aes(AesKey::Aes128([0; 16]));
        let usage = KeyUse::ENCRYPT_DECRYPT;
        let key_type = KeyType::AES_128_CBC_PKCS7_PADDING;
        let policy = KeyPolicy {
            usage,
            keyLifetime: KeyLifetime::PORTABLE,
            keyPermissions: Vec::new(),
            keyType: key_type,
            keyManagementKey: false,
        };
        let key = hw_key.importClearKey(&aes_key_material, &policy).expect("couldn't import key");

        let sealing_client_policy =
            hw_key.getCurrentDicePolicy().expect("couldn't get sealing policy");

        let token = key.getShareableToken(&sealing_client_policy);
        expect!(token.is_ok(), "couldn't get shareadble token");
        let token = token.unwrap();

        let bad_client_policy = assert_ok!(
            ClientPolicyWrapper::new_current(&connection_info_second_identity()),
            "couldn't create DICE policy"
        );
        let bad_client_policy = assert_ok!(bad_client_policy.encrypt(), "couldn't encrypt policy");

        let key = hw_key.keyTokenImport(&token, &bad_client_policy);
        expect!(key.is_err(), "shouldn't be able to import key using the wrong DICE policy");
    }
}
