/*
 * Copyright (C) 2023 The Android Open Source Project
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

use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
    types::{
        AesCipherMode::AesCipherMode, AesKey::AesKey, CipherModeParameters::CipherModeParameters,
        ExplicitKeyMaterial::ExplicitKeyMaterial, KeyLifetime::KeyLifetime, KeyType::KeyType,
        KeyUse::KeyUse, OperationData::OperationData,
        SymmetricCryptoParameters::SymmetricCryptoParameters,
        SymmetricOperation::SymmetricOperation,
        SymmetricOperationParameters::SymmetricOperationParameters,
    },
    CryptoOperation::CryptoOperation,
    CryptoOperationSet::CryptoOperationSet,
    ICryptoOperationContext::ICryptoOperationContext,
    KeyPolicy::KeyPolicy,
    OperationParameters::OperationParameters,
};
use binder::Strong;
use std::collections::HashMap;
use test::{assert_ok, expect};

use crate::tests::get_hwcryptokey;

#[derive(Debug, Clone, PartialEq)]
enum OPERATION {
    ENCRYPT,
    DECRYPT,
}

#[derive(Debug, Clone, PartialEq)]
enum MODE {
    CBC,
    CTR,
}

#[derive(Debug)]
struct Vector {
    op: Option<OPERATION>,
    mode: Option<MODE>,
    key_length: Option<u16>,
    iv_size: Option<u16>,
    payload_size: Option<u16>,
    params: HashMap<String, String>,
}

#[test]
fn aes_vector_test() {
    run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/KAT_AES/CBCGFSbox128.rsp")));
    run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/KAT_AES/CBCGFSbox256.rsp")));
    run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/KAT_AES/CBCKeySbox128.rsp")));
    run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/KAT_AES/CBCKeySbox256.rsp")));
    run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/KAT_AES/CBCVarKey128.rsp")));
    run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/KAT_AES/CBCVarKey256.rsp")));
    run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/KAT_AES/CBCVarTxt128.rsp")));
    run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/KAT_AES/CBCVarTxt256.rsp")));

    run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/aesmmt/CBCMMT128.rsp")));
    run_aes_vectors(parse_vectors(include_str!("vectors/CAVP/aesmmt/CBCMMT256.rsp")));

    run_aes_vectors(parse_vectors(include_str!("vectors/NIST/CTR/ctr_128.rsp")));
    run_aes_vectors(parse_vectors(include_str!("vectors/NIST/CTR/ctr_256.rsp")));
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 == 0 {
        (0..s.len())
            .step_by(2)
            .map(|i| s.get(i..i + 2).and_then(|sub| u8::from_str_radix(sub, 16).ok()))
            .collect()
    } else {
        None
    }
}

fn parse_vectors(raw: &str) -> Vec<Vector> {
    let mut vectors: Vec<Vector> = Vec::new();

    let mut params: HashMap<String, String> = HashMap::new();
    let mut mode: Option<MODE> = None;
    let mut op: Option<OPERATION> = None;
    let mut key_length: Option<u16> = None;
    let mut iv_size: Option<u16> = None;
    let mut payload_size: Option<u16>;

    for line in raw.lines() {
        // Check for header settings
        if line.contains("test data for") {
            let parts: Vec<&str> = line.split("test data for").collect();
            let mode_str = parts[1].trim();

            match mode_str {
                "CBC" => {
                    mode = Some(MODE::CBC);
                    iv_size = Some(128);
                }
                "CTR" => {
                    mode = Some(MODE::CTR);
                    iv_size = Some(128);
                }
                _ => {
                    mode = None;
                    iv_size = None;
                }
            };
        }

        // Check for key length
        if line.contains("Key Length") {
            let parts: Vec<&str> = line.split(":").collect();
            key_length = Some(parts[1].trim().parse::<u16>().unwrap());
        }

        // Check for encrypt or decrypt
        if line.contains("[ENCRYPT]") {
            op = Some(OPERATION::ENCRYPT);
        }

        if line.contains("[DECRYPT]") {
            op = Some(OPERATION::DECRYPT);
        }

        // Check for vector components
        if line.contains("=") {
            let words: Vec<_> = line.split_whitespace().filter(|s| s != &"=").collect();
            params.insert(words[0].to_string(), words[1].to_string());
        }

        // Check for vector completion
        if line.trim().len() == 0 && params.len() > 0 {
            // Vector complete, add to array
            payload_size = Some((params["PLAINTEXT"].len() * 4).try_into().unwrap());

            let current_vector = Vector {
                op: op.clone(),
                mode: mode.clone(),
                key_length: key_length.clone(),
                iv_size: iv_size.clone(),
                payload_size: payload_size.clone(),
                params: params.clone(),
            };
            params.clear();
            vectors.push(current_vector);
        }
    }

    // Add last vector to array if not yet added
    if params.len() > 0 {
        payload_size = Some((params["PLAINTEXT"].len() * 4).try_into().unwrap());

        let current_vector = Vector {
            op: op.clone(),
            mode: mode.clone(),
            key_length: key_length.clone(),
            iv_size: iv_size.clone(),
            payload_size: payload_size.clone(),
            params: params.clone(),
        };
        params.clear();
        vectors.push(current_vector);
    }

    vectors
}

fn get_key_type(key_length: &u16, mode: &MODE) -> Option<KeyType> {
    match key_length {
        128 => match mode {
            MODE::CBC => Some(KeyType::AES_128_CBC_NO_PADDING),
            MODE::CTR => Some(KeyType::AES_128_CTR),
        },
        256 => match mode {
            MODE::CBC => Some(KeyType::AES_256_CBC_NO_PADDING),
            MODE::CTR => Some(KeyType::AES_256_CTR),
        },
        _ => None,
    }
}

fn run_aes_vectors(vectors: Vec<Vector>) {
    let hw_crypto = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
    let hw_crypto_ops = hw_crypto.get_hwcrypto_operations().expect("couldn't get key crypto ops.");

    let mut current_key: Vec<u8> = Vec::new();
    let mut current_iv: Vec<u8> = Vec::new();
    let mut new_iv: bool;

    let mut context: Option<Strong<dyn ICryptoOperationContext>> = None;

    for v in vectors {
        if v.params.contains_key("IV") {
            current_key = hex_to_bytes(v.params["KEY"].as_str()).expect("Bad hex value");
            expect!(current_key.len() * 8 == v.key_length.unwrap() as usize, "Invalid key length");

            current_iv = hex_to_bytes(v.params["IV"].as_str()).expect("Bad hex value");
            expect!(current_iv.len() * 8 == v.iv_size.unwrap() as usize, "Invalid IV length");

            new_iv = true;
            context = None;
        } else {
            new_iv = false;
        }

        let plaintext: Vec<u8> =
            hex_to_bytes(v.params["PLAINTEXT"].as_str()).expect("Bad hex value");
        let ciphertext: Vec<u8> =
            hex_to_bytes(v.params["CIPHERTEXT"].as_str()).expect("Bad hex value");

        expect!(plaintext.len() * 8 == v.payload_size.unwrap() as usize, "Invalid data length");
        expect!(ciphertext.len() * 8 == v.payload_size.unwrap() as usize, "Invalid data length");

        let policy = KeyPolicy {
            usage: KeyUse::ENCRYPT_DECRYPT,
            keyLifetime: KeyLifetime::PORTABLE,
            keyPermissions: Vec::new(),
            keyType: get_key_type(&((current_key.len() * 8) as u16), &v.mode.as_ref().unwrap())
                .expect("Invalid key size or mode"),
            keyManagementKey: false,
        };

        let aes_key_material: ExplicitKeyMaterial = match current_key.len() * 8 {
            128 => ExplicitKeyMaterial::Aes(AesKey::Aes128(
                current_key.clone().try_into().expect("Bad key"),
            )),
            256 => ExplicitKeyMaterial::Aes(AesKey::Aes256(
                current_key.clone().try_into().expect("Bad key"),
            )),
            _ => panic!("Unsupported key length"),
        };

        let key = hw_crypto
            .import_clear_key(&aes_key_material, &policy)
            .expect("Couldn't import clear key");

        let parameters = match v.mode.clone().unwrap() {
            MODE::CBC => SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
                nonce: current_iv.clone().try_into().expect("Failed to set IV"),
            })),
            MODE::CTR => SymmetricCryptoParameters::Aes(AesCipherMode::Ctr(CipherModeParameters {
                nonce: current_iv.clone().try_into().expect("Failed to set IV"),
            })),
        };

        let direction = match v.op.as_ref().unwrap() {
            OPERATION::ENCRYPT => SymmetricOperation::ENCRYPT,
            OPERATION::DECRYPT => SymmetricOperation::DECRYPT,
        };

        let sym_op_params =
            SymmetricOperationParameters { key: Some(key.clone()), direction, parameters };
        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);

        let mut cmd_list = Vec::<CryptoOperation>::new();
        let data_output = OperationData::DataBuffer(Vec::new());

        // Build command list
        cmd_list.push(CryptoOperation::DataOutput(data_output));

        if v.mode.clone().unwrap() != MODE::CTR || new_iv {
            cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
            // For CTR, only do this when IV changes
        }

        let input_data = match v.op.as_ref().unwrap() {
            OPERATION::ENCRYPT => OperationData::DataBuffer(plaintext.clone()),
            OPERATION::DECRYPT => OperationData::DataBuffer(ciphertext.clone()),
        };
        cmd_list.push(CryptoOperation::DataInput(input_data));

        if v.mode.clone().unwrap() != MODE::CTR {
            cmd_list.push(CryptoOperation::Finish(None)); // For CTR, don't do this
        }

        if v.mode.clone().unwrap() != MODE::CTR {
            // Clear context unless processing CTR vectors
            context = None;
        }

        let crypto_op_set = CryptoOperationSet { context: context.clone(), operations: cmd_list };
        let mut crypto_sets = Vec::new();
        crypto_sets.push(crypto_op_set);

        let mut op_result =
            hw_crypto_ops.processCommandList(&mut crypto_sets).expect("couldn't process commands");

        // Capture context to be used with CTR vectors whenever we have a new IV
        if new_iv {
            context = op_result.remove(0).context;
        }

        // Verify results
        let CryptoOperation::DataOutput(OperationData::DataBuffer(processed_data)) =
            crypto_sets.remove(0).operations.remove(0)
        else {
            panic!("not reachable, we created this object above on the test");
        };

        match v.op.as_ref().unwrap() {
            OPERATION::ENCRYPT => {
                expect!(processed_data.to_vec() == ciphertext, "Known answer mismatch")
            }
            OPERATION::DECRYPT => {
                expect!(processed_data.to_vec() == plaintext, "Known answer mismatch")
            }
        };
    }
}
