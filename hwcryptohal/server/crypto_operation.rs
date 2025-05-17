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

//! Module providing a shim for the different crypto operations.

use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::{
    HmacOperationParameters::HmacOperationParameters, KeyUse::KeyUse,
    SymmetricCryptoParameters::SymmetricCryptoParameters, SymmetricOperation::SymmetricOperation,
};
use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
    OperationParameters::OperationParameters, PatternParameters::PatternParameters,
};
use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
use kmr_common::crypto::{
    self, Aes, Hmac, KeyMaterial, SymmetricOperation as CryptoSymmetricOperation,
};

use crate::cmd_processing::DataToProcess;
use crate::crypto_provider;
use crate::helpers;
use crate::opaque_key::OpaqueKey;

// Pattern for cbcs operations. cbcs is based on partially encryption using AES-CBC as defined in
// IEC 23001-7:2016
enum CbcsPattern {
    Protected(usize),
    Clear(usize),
}

struct CbcsPatternParams {
    num_encrypted_bytes: usize,
    num_clear_bytes: usize,
    current_pattern: CbcsPattern,
}

impl CbcsPatternParams {
    fn new(pattern_parameters: &PatternParameters) -> Result<Self, HwCryptoError> {
        let mut num_encrypted_blocks: usize =
            pattern_parameters.numberBlocksProcess.try_into().map_err(|e| {
                hwcrypto_err!(BAD_PARAMETER, "number encrypted blocks cannot be negative: {:?}", e)
            })?;
        let num_clear_blocks: usize =
            pattern_parameters.numberBlocksCopy.try_into().map_err(|e| {
                hwcrypto_err!(BAD_PARAMETER, "number clear blocks cannot be negative: {:?}", e)
            })?;
        // Special case. Some encoders pass a 0,0 to represent full sample encryption. Treating it
        // the same as 1, 0.
        if (num_encrypted_blocks == 0) && (num_clear_blocks == 0) {
            num_encrypted_blocks = 1;
        }
        let num_encrypted_bytes = num_encrypted_blocks
            .checked_mul(crypto::aes::BLOCK_SIZE)
            .ok_or(hwcrypto_err!(BAD_PARAMETER, "number encrypted blocks was too high"))?;
        let num_clear_bytes = num_clear_blocks
            .checked_mul(crypto::aes::BLOCK_SIZE)
            .ok_or(hwcrypto_err!(BAD_PARAMETER, "number clear blocks was too high"))?;
        // Patterns starts with a number of protected blocks
        let current_pattern = CbcsPattern::Protected(num_encrypted_bytes);
        Ok(Self { num_encrypted_bytes, num_clear_bytes, current_pattern })
    }
}

pub(crate) trait ICryptographicOperation: Send {
    // Returns the required minimum size in bytes the output buffer needs to have for the given
    // `input`
    fn get_operation_req_size(
        &self,
        input: Option<&DataToProcess>,
        is_finish: bool,
    ) -> Result<usize, HwCryptoError>;

    fn operation<'a>(
        &mut self,
        input: Option<&mut DataToProcess<'a>>,
        output: &mut DataToProcess<'a>,
        is_finish: bool,
    ) -> Result<usize, HwCryptoError>;

    fn is_active(&self) -> bool;

    fn is_valid(&self) -> bool;

    #[allow(dead_code)]
    fn update_aad(&mut self, _input: &DataToProcess) -> Result<(), HwCryptoError> {
        Err(hwcrypto_err!(
            BAD_PARAMETER,
            "update aad only valid for authenticated symmetric operations"
        ))
    }

    fn set_operation_pattern(
        &mut self,
        _patter_parameter: &PatternParameters,
    ) -> Result<(), HwCryptoError> {
        Err(hwcrypto_err!(BAD_PARAMETER, "set_operation_pattern only supported for AES CBC"))
    }
}

trait IBaseCryptoOperation: Send {
    fn update<'a>(
        &mut self,
        input: &mut DataToProcess<'a>,
        output: &mut DataToProcess<'a>,
    ) -> Result<usize, HwCryptoError>;

    fn finish(&mut self, output: &mut DataToProcess) -> Result<usize, HwCryptoError>;

    fn get_req_size_finish(&self) -> Result<usize, HwCryptoError>;

    fn get_req_size_update(&self, input: &DataToProcess) -> Result<usize, HwCryptoError>;

    fn is_active(&self) -> bool;

    fn is_valid(&self) -> bool;

    fn update_aad(&mut self, _input: &DataToProcess) -> Result<(), HwCryptoError> {
        Err(hwcrypto_err!(
            BAD_PARAMETER,
            "update aad only valid for authenticated symmetric operations"
        ))
    }

    fn set_operation_pattern(
        &mut self,
        patter_parameter: &PatternParameters,
    ) -> Result<(), HwCryptoError>;
}

impl<T: IBaseCryptoOperation> ICryptographicOperation for T {
    fn get_operation_req_size(
        &self,
        input: Option<&DataToProcess>,
        is_finish: bool,
    ) -> Result<usize, HwCryptoError> {
        if is_finish {
            self.get_req_size_finish()
        } else {
            let input =
                input.ok_or_else(|| hwcrypto_err!(BAD_PARAMETER, "input was not provided"))?;
            self.get_req_size_update(input)
        }
    }

    fn operation<'a>(
        &mut self,
        mut input: Option<&mut DataToProcess<'a>>,
        output: &mut DataToProcess<'a>,
        is_finish: bool,
    ) -> Result<usize, HwCryptoError> {
        if is_finish {
            self.finish(output)
        } else {
            let input =
                input.take().ok_or(hwcrypto_err!(BAD_PARAMETER, "input was not provided"))?;
            self.update(input, output)
        }
    }

    fn is_active(&self) -> bool {
        self.is_active()
    }

    fn is_valid(&self) -> bool {
        self.is_valid()
    }

    fn update_aad(&mut self, input: &DataToProcess) -> Result<(), HwCryptoError> {
        self.update_aad(input)
    }

    fn set_operation_pattern(
        &mut self,
        patter_parameter: &PatternParameters,
    ) -> Result<(), HwCryptoError> {
        self.set_operation_pattern(patter_parameter)
    }
}

// Newtype used because the traits we currently use for cryptographic operations cannot directly
// either process `VolatileSlice`s or use pointers to memory, so we need to make a copy of the data.
// TODO: refactor traits to not require copying the input for VolatileSlices
struct TempBuffer(Vec<u8>);

impl TempBuffer {
    fn new() -> Self {
        TempBuffer(Vec::new())
    }

    fn read_into_buffer_reference<'a>(
        &'a mut self,
        input: &'a mut DataToProcess,
        len: Option<usize>,
    ) -> Result<&'a [u8], HwCryptoError> {
        let len = len.unwrap_or(input.len());
        if len > input.len() {
            return Err(hwcrypto_err!(
                BAD_PARAMETER,
                "end {} out of slice bounds for slice size {}",
                len,
                input.len()
            ));
        }

        if !input.is_non_volatile_slice_backed() {
            let slice = input.try_slice(len)?;
            Ok(slice)
        } else {
            self.0.clear();
            self.0.try_reserve(len)?;
            // Addition should be safe because try_reserve didn't fail
            self.0.resize_with(len, Default::default);
            input.read_into_slice(self.0.as_mut_slice(), Some(len))?;
            Ok(&self.0[..])
        }
    }
}

pub(crate) struct HmacOperation {
    opaque_key: OpaqueKey,
    accumulating_op: Option<Box<dyn crypto::AccumulatingOperation>>,
}

impl HmacOperation {
    fn new(parameters: &HmacOperationParameters) -> Result<Self, HwCryptoError> {
        let opaque_key: OpaqueKey = parameters
            .key
            .as_ref()
            .ok_or(hwcrypto_err!(BAD_PARAMETER, "hmac key not provided"))?
            .try_into()?;
        Self::check_parameters(&opaque_key, parameters)?;
        let digest = helpers::aidl_to_rust_digest(&opaque_key.get_key_type())?;
        let hmac = crypto_provider::HmacImpl;
        let accumulating_op = match opaque_key.key_material {
            KeyMaterial::Hmac(ref key) => hmac.begin(key.clone(), digest).map_err(|e| {
                hwcrypto_err!(GENERIC_ERROR, "couldn't begin hmac operation: {:?}", e)
            }),
            _ => Err(hwcrypto_err!(BAD_PARAMETER, "Invalid key type for HMAC operation")),
        }?;
        Ok(HmacOperation { opaque_key, accumulating_op: Some(accumulating_op) })
    }

    fn check_parameters(
        opaque_key: &OpaqueKey,
        _parameters: &HmacOperationParameters,
    ) -> Result<(), HwCryptoError> {
        if !opaque_key.key_usage_supported(KeyUse::SIGN) {
            return Err(hwcrypto_err!(BAD_PARAMETER, "Provided key cannot be used for signing"));
        }
        opaque_key.expiration_time_valid()?;
        match &opaque_key.key_material {
            KeyMaterial::Hmac(_) => Ok(()),
            _ => Err(hwcrypto_err!(BAD_PARAMETER, "Invalid key type for HMAC operation")),
        }
    }
}

impl IBaseCryptoOperation for HmacOperation {
    fn get_req_size_update(&self, _input: &DataToProcess) -> Result<usize, HwCryptoError> {
        Ok(0)
    }

    fn get_req_size_finish(&self) -> Result<usize, HwCryptoError> {
        Ok(crypto_provider::HMAC_MAX_SIZE)
    }

    fn update(
        &mut self,
        input: &mut DataToProcess,
        _output: &mut DataToProcess,
    ) -> Result<usize, HwCryptoError> {
        let op = self
            .accumulating_op
            .as_mut()
            .ok_or(hwcrypto_err!(BAD_STATE, "operation was already finished"))?;
        // TODO: refactor traits to not require copying the input for VolatileSlices
        let mut input_buffer = TempBuffer::new();
        let input_data = input_buffer.read_into_buffer_reference(input, None)?;
        op.update(input_data)?;
        Ok(0)
    }

    fn finish(&mut self, output: &mut DataToProcess) -> Result<usize, HwCryptoError> {
        let op = self
            .accumulating_op
            .take()
            .ok_or(hwcrypto_err!(BAD_STATE, "operation was already finished"))?;
        let req_size = self.get_req_size_finish()?;
        if output.len() != req_size {
            return Err(hwcrypto_err!(BAD_PARAMETER, "input size was not {}", req_size));
        }
        let output_data = op.finish()?;
        let output_len = output_data.len();
        output.append_slice(output_data.as_slice())?;
        Ok(output_len)
    }

    fn is_active(&self) -> bool {
        self.accumulating_op.is_some()
    }

    fn is_valid(&self) -> bool {
        self.opaque_key.expiration_time_valid().is_ok()
    }

    fn set_operation_pattern(
        &mut self,
        _patter_parameter: &PatternParameters,
    ) -> Result<(), HwCryptoError> {
        Err(hwcrypto_err!(BAD_PARAMETER, "set_operation_pattern only supported for AES CBC"))
    }
}

pub(crate) struct AesOperation {
    opaque_key: OpaqueKey,
    emitting_op: Option<Box<dyn crypto::EmittingOperation>>,
    dir: CryptoSymmetricOperation,
    remaining_unaligned_data_size: usize,
    block_based_encryption: bool,
    cbcs_pattern: Option<CbcsPatternParams>,
    operation_started: bool,
}

impl AesOperation {
    fn new(
        opaque_key: OpaqueKey,
        dir: SymmetricOperation,
        parameters: &SymmetricCryptoParameters,
    ) -> Result<Self, HwCryptoError> {
        AesOperation::check_cipher_parameters(&opaque_key, dir, parameters)?;
        let key_material = &opaque_key.key_material;
        let dir = helpers::aidl_to_rust_symmetric_direction(dir)?;
        let emitting_op = match key_material {
            KeyMaterial::Aes(key) => {
                let aes = crypto_provider::AesImpl;
                let mode = helpers::aidl_to_rust_aes_cipher_params(parameters, &opaque_key)?;
                aes.begin(key.clone(), mode, dir).map_err(|e| {
                    hwcrypto_err!(GENERIC_ERROR, "couldn't begin aes operation: {:?}", e)
                })
            }
            _ => Err(hwcrypto_err!(BAD_PARAMETER, "Invalid key type for AES symmetric operation")),
        }?;
        let block_based_encryption = helpers::symmetric_encryption_block_based(parameters)?;
        let aes_operation = Self {
            opaque_key,
            emitting_op: Some(emitting_op),
            dir,
            remaining_unaligned_data_size: 0,
            block_based_encryption,
            cbcs_pattern: None,
            operation_started: false,
        };
        Ok(aes_operation)
    }

    fn check_cipher_parameters(
        opaque_key: &OpaqueKey,
        dir: SymmetricOperation,
        parameters: &SymmetricCryptoParameters,
    ) -> Result<(), HwCryptoError> {
        opaque_key.expiration_time_valid()?;
        opaque_key.symmetric_operation_is_compatible(dir)?;
        opaque_key.parameters_are_compatible_symmetric_cipher(parameters)
    }

    // Returns the size required to process the current block and how much extra data was cached for
    // a future call
    fn get_update_req_size_with_remainder(
        &self,
        input: &DataToProcess,
    ) -> Result<(usize, usize), HwCryptoError> {
        let input_size = input.len();
        self.get_req_size_from_len(input_size)
    }

    fn get_req_size_from_len(&self, input_len: usize) -> Result<(usize, usize), HwCryptoError> {
        if self.block_based_encryption {
            match self.dir {
                CryptoSymmetricOperation::Encrypt => {
                    let input_size = input_len + self.remaining_unaligned_data_size;
                    let extra_data_len = input_size % crypto::aes::BLOCK_SIZE;
                    Ok((input_size - extra_data_len, extra_data_len))
                }
                CryptoSymmetricOperation::Decrypt => {
                    Ok((AesOperation::round_to_block_size(input_len), 0))
                }
            }
        } else {
            Ok((input_len, 0))
        }
    }

    fn round_to_block_size(size: usize) -> usize {
        ((size + crypto::aes::BLOCK_SIZE - 1) / crypto::aes::BLOCK_SIZE) * crypto::aes::BLOCK_SIZE
    }

    fn cbcs_update<'a>(
        &mut self,
        input: &mut DataToProcess<'a>,
        output: &mut DataToProcess<'a>,
    ) -> Result<usize, HwCryptoError> {
        let mut total_pattern_size = input.len();
        let unencrypted_bytes_last_block = total_pattern_size % crypto::aes::BLOCK_SIZE;
        if unencrypted_bytes_last_block != 0 {
            // on cbcs if there are remainders on the last block, then those need to be directly
            // copied, they will be unencrypted
            total_pattern_size -= unencrypted_bytes_last_block;
        }
        if output.len() != input.len() {
            return Err(hwcrypto_err!(BAD_PARAMETER, "output size was not {}", input.len()));
        }
        let cbcs_pattern = self
            .cbcs_pattern
            .as_mut()
            .ok_or(hwcrypto_err!(BAD_PARAMETER, "not a cbcs operation"))?;
        // TODO: refactor to remove need of input copy for memory slices
        let mut input_buff = TempBuffer::new();
        let mut remaining_len = total_pattern_size;
        let aes_op = self
            .emitting_op
            .as_mut()
            .ok_or(hwcrypto_err!(BAD_STATE, "operation was already finished"))?;
        while remaining_len > 0 {
            match cbcs_pattern.current_pattern {
                CbcsPattern::Protected(num_encrypted_bytes) => {
                    let encrypted_bytes = std::cmp::min(remaining_len, num_encrypted_bytes);
                    let input_data =
                        input_buff.read_into_buffer_reference(input, Some(encrypted_bytes))?;
                    let output_data = aes_op.update(input_data)?;
                    output.append_slice(output_data.as_slice())?;
                    if remaining_len > num_encrypted_bytes {
                        // There is still data to process, advance index and change pattern to clear
                        // In this case encrypted_bytes == num_encrypted_bytes
                        cbcs_pattern.current_pattern =
                            CbcsPattern::Clear(cbcs_pattern.num_clear_bytes);
                    } else {
                        // We processed all available data, check if we should change pattern or
                        // keep the same
                        if num_encrypted_bytes > remaining_len {
                            // We are still on the protected pattern area
                            cbcs_pattern.current_pattern =
                                CbcsPattern::Protected(num_encrypted_bytes - remaining_len);
                        } else {
                            // We need to switch to a clear area
                            cbcs_pattern.current_pattern =
                                CbcsPattern::Clear(cbcs_pattern.num_clear_bytes);
                        }
                        break;
                    }
                    remaining_len -= num_encrypted_bytes;
                }
                CbcsPattern::Clear(num_clear_bytes) => {
                    let clear_bytes = std::cmp::min(remaining_len, num_clear_bytes);
                    output.read_from_slice(input, Some(clear_bytes))?;
                    if remaining_len > num_clear_bytes {
                        // There is still data to process, advance index and change pattern to
                        // protected. In this case clear_bytes == num_clear_bytes
                        cbcs_pattern.current_pattern =
                            CbcsPattern::Protected(cbcs_pattern.num_encrypted_bytes);
                    } else {
                        // We processed all available data, check if we should change pattern or
                        // keep the same
                        if num_clear_bytes > remaining_len {
                            // We are still on the clear pattern area
                            cbcs_pattern.current_pattern =
                                CbcsPattern::Clear(num_clear_bytes - remaining_len);
                        } else {
                            // We need to switch to a protected area
                            cbcs_pattern.current_pattern =
                                CbcsPattern::Protected(cbcs_pattern.num_encrypted_bytes);
                        }
                        break;
                    }
                    remaining_len -= num_clear_bytes;
                }
            }
        }
        if unencrypted_bytes_last_block != 0 {
            output.read_from_slice(input, Some(unencrypted_bytes_last_block))?;
        }
        Ok(total_pattern_size + unencrypted_bytes_last_block)
    }
}

impl IBaseCryptoOperation for AesOperation {
    fn update<'a>(
        &mut self,
        input: &mut DataToProcess<'a>,
        output: &mut DataToProcess<'a>,
    ) -> Result<usize, HwCryptoError> {
        self.operation_started = true;
        if self.cbcs_pattern.is_some() {
            return self.cbcs_update(input, output);
        }
        let (req_size, unaligned_size) = self.get_update_req_size_with_remainder(&input)?;
        if output.len() != req_size {
            return Err(hwcrypto_err!(BAD_PARAMETER, "input size was not {}", req_size));
        }
        let op = self
            .emitting_op
            .as_mut()
            .ok_or(hwcrypto_err!(BAD_STATE, "operation was already finished"))?;
        // TODO: refactor traits to not require copying the input for VolatileSlices
        let mut input_buffer = TempBuffer::new();
        let input_data = input_buffer.read_into_buffer_reference(input, None)?;
        let output_data = op.update(input_data)?;
        let output_len = output_data.len();
        output.append_slice(output_data.as_slice())?;
        self.remaining_unaligned_data_size = unaligned_size;
        Ok(output_len)
    }

    fn finish(&mut self, output: &mut DataToProcess) -> Result<usize, HwCryptoError> {
        let op = self
            .emitting_op
            .take()
            .ok_or(hwcrypto_err!(BAD_STATE, "operation was already finished"))?;
        let req_size = self.get_req_size_finish()?;
        if output.len() != req_size {
            return Err(hwcrypto_err!(BAD_PARAMETER, "input size was not {}", req_size));
        }
        let output_data = op.finish()?;
        let output_len = output_data.len();
        output.append_slice(output_data.as_slice())?;
        self.remaining_unaligned_data_size = 0;
        self.operation_started = false;
        Ok(output_len)
    }

    fn update_aad(&mut self, _input: &DataToProcess) -> Result<(), HwCryptoError> {
        unimplemented!("GCM AES note supported yet");
    }

    fn get_req_size_finish(&self) -> Result<usize, HwCryptoError> {
        if self.cbcs_pattern.is_some() {
            // On CBCS patterns we do not have more data to write on finish, because there is no
            // padding needed and all operations were done using block boundaries.
            Ok(0)
        } else {
            let (req_size_to_process, _) = self.get_req_size_from_len(0)?;
            match self.dir {
                CryptoSymmetricOperation::Encrypt => {
                    Ok(req_size_to_process + crypto::aes::BLOCK_SIZE)
                }
                CryptoSymmetricOperation::Decrypt => Ok(crypto::aes::BLOCK_SIZE),
            }
        }
    }

    fn get_req_size_update(&self, input: &DataToProcess) -> Result<usize, HwCryptoError> {
        if self.cbcs_pattern.is_some() {
            // On CBCS patterns we are currently processing all the input at once (remaining bytes
            // that are not multiples of a block are copied unencrypted) so the space needed is
            // always the size of the input.
            Ok(input.len())
        } else {
            let (req_size, _) = self.get_update_req_size_with_remainder(input)?;
            Ok(req_size)
        }
    }

    fn is_active(&self) -> bool {
        self.emitting_op.is_some()
    }

    fn is_valid(&self) -> bool {
        self.opaque_key.expiration_time_valid().is_ok()
    }

    fn set_operation_pattern(
        &mut self,
        pattern_parameters: &PatternParameters,
    ) -> Result<(), HwCryptoError> {
        self.opaque_key.supports_pattern_encryption()?;
        // We only support setting a pattern if we have not started encrypting/decrypting
        if self.operation_started {
            return Err(hwcrypto_err!(BAD_STATE, "pattern cannot be set if operation has started"));
        }
        // We do not support changing an already set up pattern
        if self.cbcs_pattern.is_some() {
            return Err(hwcrypto_err!(BAD_STATE, "pattern has already been set"));
        }
        self.cbcs_pattern = Some(CbcsPatternParams::new(pattern_parameters)?);
        Ok(())
    }
}

pub(crate) struct CopyOperation;

impl ICryptographicOperation for CopyOperation {
    fn get_operation_req_size(
        &self,
        input: Option<&DataToProcess>,
        _is_finish: bool,
    ) -> Result<usize, HwCryptoError> {
        let input = input.ok_or_else(|| hwcrypto_err!(BAD_PARAMETER, "input was not provided"))?;
        Ok(input.len())
    }

    fn operation<'a>(
        &mut self,
        input: Option<&mut DataToProcess<'a>>,
        output: &mut DataToProcess<'a>,
        _is_finish: bool,
    ) -> Result<usize, HwCryptoError> {
        let num_bytes_copy = self.get_operation_req_size(input.as_deref(), false)?;
        let mut input =
            input.ok_or_else(|| hwcrypto_err!(BAD_PARAMETER, "input was not provided"))?;
        output.read_from_slice(&mut input, None)?;
        Ok(num_bytes_copy)
    }

    fn is_active(&self) -> bool {
        true
    }

    fn is_valid(&self) -> bool {
        true
    }
}

pub(crate) struct CryptographicOperation;

impl CryptographicOperation {
    pub(crate) fn new_binder(
        crypto_operation_parameters: &OperationParameters,
    ) -> Result<Box<dyn ICryptographicOperation>, HwCryptoError> {
        match crypto_operation_parameters {
            OperationParameters::SymmetricCrypto(symmetric_params) => {
                if let Some(key) = &symmetric_params.key {
                    let opaque_key: OpaqueKey = key.try_into()?;
                    let dir = symmetric_params.direction;
                    let parameters = &symmetric_params.parameters;
                    AesOperation::check_cipher_parameters(&opaque_key, dir, parameters)?;
                    let aes_operation = AesOperation::new(opaque_key, dir, parameters)?;
                    Ok(Box::new(aes_operation))
                } else {
                    Err(hwcrypto_err!(BAD_PARAMETER, "key was null"))
                }
            }
            OperationParameters::Hmac(params) => {
                let hmac_op = HmacOperation::new(params)?;
                Ok(Box::new(hmac_op))
            }
            _ => unimplemented!("operation not implemented yet"),
        }
    }
}

// Implementing ICryptographicOperation for () to use it as a type for when we need to pass a `None`
// on an `Option<&impl ICryptographicOperation>`
impl ICryptographicOperation for () {
    fn get_operation_req_size(
        &self,
        _input: Option<&DataToProcess>,
        _is_finish: bool,
    ) -> Result<usize, HwCryptoError> {
        Err(hwcrypto_err!(UNSUPPORTED, "cannot get size for null operation"))
    }

    fn operation(
        &mut self,
        _input: Option<&mut DataToProcess>,
        _output: &mut DataToProcess,
        _is_finish: bool,
    ) -> Result<usize, HwCryptoError> {
        Err(hwcrypto_err!(UNSUPPORTED, "nothing to execute on null operation"))
    }

    fn is_active(&self) -> bool {
        false
    }

    fn is_valid(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::{
        AesCipherMode::AesCipherMode, CipherModeParameters::CipherModeParameters,
        KeyLifetime::KeyLifetime,
        KeyType::KeyType, KeyUse::KeyUse,
        SymmetricCryptoParameters::SymmetricCryptoParameters,
        SymmetricOperation::SymmetricOperation,
        SymmetricOperationParameters::SymmetricOperationParameters,
    };
    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
        KeyPolicy::KeyPolicy,
    };
    use test::{expect, expect_eq};

    use crate::tests::connection_info;

    #[test]
    fn use_aes_key() {
        let usage = KeyUse::ENCRYPT_DECRYPT;
        let key_type = KeyType::AES_256_CBC_PKCS7_PADDING;
        let policy = KeyPolicy {
            usage,
            keyLifetime: KeyLifetime::EPHEMERAL,
            keyPermissions: Vec::new(),
            keyType: key_type,
            keyManagementKey: false,
        };
        let handle = OpaqueKey::generate_opaque_key(&policy, &connection_info())
            .expect("couldn't generate key");
        let nonce = [0u8; 16];
        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
            nonce: nonce.into(),
        }));
        let direction = SymmetricOperation::ENCRYPT;
        let sym_op_params =
            SymmetricOperationParameters { key: Some(handle.clone()), direction, parameters };
        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
        let input_to_encrypt = "hello world1234";
        let mut input_data = input_to_encrypt.as_bytes().to_vec();
        let mut input_slice = DataToProcess::new_from_slice(&mut input_data[..]);
        let mut op =
            CryptographicOperation::new_binder(&op_params).expect("couldn't create aes operation");
        let req_size = op
            .get_operation_req_size(Some(&input_slice), false)
            .expect("couldn't get required_size");
        expect_eq!(req_size, 0, "Required size for encryptiong less than a block should be 0");
        let mut output_data = vec![];
        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[..]);
        let written_bytes = op
            .operation(Some(&mut input_slice), &mut output_slice, false)
            .expect("couldn't update");
        expect_eq!(written_bytes, 0, "Written bytes for encryptiong less than a block should be 0");
        let req_size_finish =
            op.get_operation_req_size(None, true).expect("couldn't get required_size");
        expect_eq!(
            req_size_finish,
            16,
            "Required size for encryptiong less than a block should be a block"
        );
        output_data.append(&mut vec![0u8; 16]);
        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[..]);
        op.operation(None, &mut output_slice, true).expect("couldn't finish");
        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[0..0]);
        let mut input_slice = DataToProcess::new_from_slice(&mut input_data[..]);
        let update_op = op.operation(Some(&mut input_slice), &mut output_slice, false);
        expect!(update_op.is_err(), "shouldn't be able to run operations anymore");
        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[0..0]);
        let finish_op = op.operation(None, &mut output_slice, true);
        expect!(finish_op.is_err(), "shouldn't be able to run operations anymore");
        let direction = SymmetricOperation::DECRYPT;
        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
            nonce: nonce.into(),
        }));
        let sym_op_params =
            SymmetricOperationParameters { key: Some(handle), direction, parameters };
        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
        let mut op =
            CryptographicOperation::new_binder(&op_params).expect("couldn't create aes operation");
        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[..]);
        let req_size = op
            .get_operation_req_size(Some(&output_slice), false)
            .expect("couldn't get required_size");
        let mut decrypted_data = vec![0; req_size];
        let mut decrypted_slice = DataToProcess::new_from_slice(&mut decrypted_data[..]);
        let mut decrypted_data_size = op
            .operation(Some(&mut output_slice), &mut decrypted_slice, false)
            .expect("couldn't update");
        let decrypted_data_start = decrypted_data_size;
        let req_size_finish =
            op.get_operation_req_size(None, true).expect("couldn't get required_size");
        let decrypted_data_end = decrypted_data_size + req_size_finish;
        let mut decrypted_slice = DataToProcess::new_from_slice(
            &mut decrypted_data[decrypted_data_start..decrypted_data_end],
        );
        let total_finish_size =
            op.operation(None, &mut decrypted_slice, true).expect("couldn't finish");
        decrypted_data_size += total_finish_size;
        decrypted_data.truncate(decrypted_data_size);
        expect_eq!(input_to_encrypt.len(), decrypted_data_size, "bad length for decrypted data");
        let decrypted_str = String::from_utf8(decrypted_data).unwrap();
        expect_eq!(input_to_encrypt, decrypted_str, "bad data decrypted");
    }

    #[test]
    fn process_aes_encrypt_decrypt_operations() {
        let usage = KeyUse::ENCRYPT_DECRYPT;
        let key_type = KeyType::AES_256_CBC_PKCS7_PADDING;
        let policy = KeyPolicy {
            usage,
            keyLifetime: KeyLifetime::EPHEMERAL,
            keyPermissions: Vec::new(),
            keyType: key_type,
            keyManagementKey: false,
        };
        let handle = OpaqueKey::generate_opaque_key(&policy, &connection_info())
            .expect("couldn't generate key");
        let nonce = [0u8; 16];
        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
            nonce: nonce.into(),
        }));
        let direction = SymmetricOperation::ENCRYPT;
        let sym_op_params =
            SymmetricOperationParameters { key: Some(handle.clone()), direction, parameters };
        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
        let mut op =
            CryptographicOperation::new_binder(&op_params).expect("couldn't create aes operation");
        let input_to_encrypt = "test encryption string";
        let mut input_data = input_to_encrypt.as_bytes().to_vec();
        let mut input_slice = DataToProcess::new_from_slice(&mut input_data[..]);
        let req_size = op
            .get_operation_req_size(Some(&input_slice), false)
            .expect("couldn't get required_size");
        expect_eq!(req_size, 16, "Implementation should try to encrypt a block in this case");
        let mut output_data = vec![0; 200];
        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[..req_size]);
        let mut total_encryption_size = 0;
        let written_bytes = op
            .operation(Some(&mut input_slice), &mut output_slice, false)
            .expect("couldn't update");
        total_encryption_size += written_bytes;
        expect_eq!(written_bytes, 16, "A block should have been encrypted");
        let input_to_encrypt_2 = " for this ";
        let mut input_data = input_to_encrypt_2.as_bytes().to_vec();
        let mut input_slice = DataToProcess::new_from_slice(&mut input_data[..]);
        let req_size = op
            .get_operation_req_size(Some(&input_slice), false)
            .expect("couldn't get required_size");
        let output_start = written_bytes;
        let output_stop = written_bytes + req_size;
        expect_eq!(req_size, 16, "Implementation should try to encrypt a block in this case");
        let mut output_slice =
            DataToProcess::new_from_slice(&mut output_data[output_start..output_stop]);
        let written_bytes = op
            .operation(Some(&mut input_slice), &mut output_slice, false)
            .expect("couldn't update");
        expect_eq!(written_bytes, 16, "A block should have been encrypted");
        total_encryption_size += written_bytes;
        let output_start = output_start + written_bytes;
        let input_to_encrypt_3 = "test";
        let mut input_data = input_to_encrypt_3.as_bytes().to_vec();
        let mut input_slice = DataToProcess::new_from_slice(&mut input_data[..]);
        let req_size = op
            .get_operation_req_size(Some(&input_slice), false)
            .expect("couldn't get required_size");
        expect_eq!(req_size, 0, "Required size for encryptiong less than a block should be 0");
        let mut output_slice =
            DataToProcess::new_from_slice(&mut output_data[output_start..output_start]);
        let written_bytes = op
            .operation(Some(&mut input_slice), &mut output_slice, false)
            .expect("couldn't update");
        total_encryption_size += written_bytes;
        expect_eq!(written_bytes, 0, "No bytes should have been written");
        let input_to_encrypt_4 = " is";
        let mut input_data = input_to_encrypt_4.as_bytes().to_vec();
        let mut input_slice = DataToProcess::new_from_slice(&mut input_data[..]);
        let req_size = op
            .get_operation_req_size(Some(&input_slice), false)
            .expect("couldn't get required_size");
        expect_eq!(req_size, 0, "Required size for encryptiong less than a block should be 0");
        let mut output_slice =
            DataToProcess::new_from_slice(&mut output_data[output_start..output_start]);
        let written_bytes = op
            .operation(Some(&mut input_slice), &mut output_slice, false)
            .expect("couldn't update");
        expect_eq!(written_bytes, 0, "No bytes should have been written");
        total_encryption_size += written_bytes;
        let input_to_encrypt_5 = " a ";
        let mut input_data = input_to_encrypt_5.as_bytes().to_vec();
        let mut input_slice = DataToProcess::new_from_slice(&mut input_data[..]);
        let req_size = op
            .get_operation_req_size(Some(&input_slice), false)
            .expect("couldn't get required_size");
        expect_eq!(req_size, 0, "Required size for encryptiong less than a block should be 0");
        let mut output_slice =
            DataToProcess::new_from_slice(&mut output_data[output_start..output_start]);
        let written_bytes = op
            .operation(Some(&mut input_slice), &mut output_slice, false)
            .expect("couldn't update");
        expect_eq!(written_bytes, 0, "No bytes should have been written");
        total_encryption_size += written_bytes;
        let input_to_encrypt_6 = "random one.";
        let mut input_data = input_to_encrypt_6.as_bytes().to_vec();
        let mut input_slice = DataToProcess::new_from_slice(&mut input_data[..]);
        let req_size = op
            .get_operation_req_size(Some(&input_slice), false)
            .expect("couldn't get required_size");
        expect_eq!(req_size, 16, "Implementation should try to encrypt a block in this case");
        let output_stop = output_start + req_size;
        let mut output_slice =
            DataToProcess::new_from_slice(&mut output_data[output_start..output_stop]);
        let written_bytes = op
            .operation(Some(&mut input_slice), &mut output_slice, false)
            .expect("couldn't update");
        total_encryption_size += written_bytes;
        expect_eq!(written_bytes, 16, "A block should have been encrypted");
        let output_start = output_start + written_bytes;
        let req_size_finish =
            op.get_operation_req_size(None, true).expect("couldn't get required_size");
        expect_eq!(
            req_size_finish,
            16,
            "Required size for encryptiong less than a block should be a block"
        );
        let output_stop = output_start + req_size_finish;
        let mut output_slice =
            DataToProcess::new_from_slice(&mut output_data[output_start..output_stop]);
        let finish_written_bytes =
            op.operation(None, &mut output_slice, true).expect("couldn't finish");
        expect_eq!(finish_written_bytes, 16, "With padding we should have written a block");
        total_encryption_size += finish_written_bytes;
        output_data.truncate(total_encryption_size);
        // Decrypting
        let mut decrypted_data_size = 0;
        let direction = SymmetricOperation::DECRYPT;
        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
            nonce: nonce.into(),
        }));
        let sym_op_params =
            SymmetricOperationParameters { key: Some(handle), direction, parameters };
        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
        let mut op =
            CryptographicOperation::new_binder(&op_params).expect("couldn't create aes operation");
        let mut decrypted_data = vec![0; total_encryption_size];
        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[..4]);
        let req_size = op
            .get_operation_req_size(Some(&output_slice), false)
            .expect("couldn't get required_size");
        expect_eq!(req_size, 16, "worse case space for this size of input is a block");
        let mut decrypted_slice = DataToProcess::new_from_slice(&mut decrypted_data[..16]);
        let written_bytes = op
            .operation(Some(&mut output_slice), &mut decrypted_slice, false)
            .expect("couldn't update");
        decrypted_data_size += written_bytes;
        expect_eq!(written_bytes, 0, "No bytes should have been written");
        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[4..32]);
        let req_size = op
            .get_operation_req_size(Some(&output_slice), false)
            .expect("couldn't get required_size");
        expect_eq!(req_size, 32, "worse case space for this size of input is 2 blocks");
        let mut decrypted_slice = DataToProcess::new_from_slice(&mut decrypted_data[..32]);
        let written_bytes = op
            .operation(Some(&mut output_slice), &mut decrypted_slice, false)
            .expect("couldn't update");
        decrypted_data_size += written_bytes;
        expect_eq!(written_bytes, 16, "One block should have been written");
        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[32..50]);
        let req_size = op
            .get_operation_req_size(Some(&output_slice), false)
            .expect("couldn't get required_size");
        expect_eq!(req_size, 32, "worse case space for this size of input is 2 blocks");
        let mut decrypted_slice = DataToProcess::new_from_slice(&mut decrypted_data[16..48]);
        let written_bytes = op
            .operation(Some(&mut output_slice), &mut decrypted_slice, false)
            .expect("couldn't update");
        decrypted_data_size += written_bytes;
        expect_eq!(written_bytes, 32, "Two block should have been written");
        let mut output_slice = DataToProcess::new_from_slice(&mut output_data[50..64]);
        let req_size = op
            .get_operation_req_size(Some(&output_slice), false)
            .expect("couldn't get required_size");
        expect_eq!(req_size, 16, "worse case space for this size of input is 1 block");
        let mut decrypted_slice = DataToProcess::new_from_slice(&mut decrypted_data[48..64]);
        let written_bytes = op
            .operation(Some(&mut output_slice), &mut decrypted_slice, false)
            .expect("couldn't update");
        decrypted_data_size += written_bytes;
        expect_eq!(written_bytes, 0, "No blocks should have been written");
        let req_size_finish =
            op.get_operation_req_size(None, true).expect("couldn't get required_size");
        expect_eq!(req_size_finish, 16, "Max size required to finish should be 1 block");
        let mut decrypted_slice = DataToProcess::new_from_slice(&mut decrypted_data[48..64]);
        let total_finish_size =
            op.operation(None, &mut decrypted_slice, true).expect("couldn't finish");
        decrypted_data_size += total_finish_size;
        decrypted_data.truncate(decrypted_data_size);
        let decrypted_msg =
            String::from_utf8(decrypted_data).expect("couldn't decode receivedd message");
        let original_msg = input_to_encrypt.to_owned()
            + input_to_encrypt_2
            + input_to_encrypt_3
            + input_to_encrypt_4
            + input_to_encrypt_5
            + input_to_encrypt_6;
        expect_eq!(original_msg.len(), decrypted_msg.len(), "bad length for decrypted data");
        expect_eq!(original_msg, decrypted_msg, "bad data decrypted");
    }
}
