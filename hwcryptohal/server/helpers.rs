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

//! Helper functions that includes data transformation for AIDL types.

/// Macro to create enums that can easily be used as cose labels for serialization
/// It expects the macro definition to have the following form:
///
/// cose_enum_gen! {
///     enum CoseEnumName {
///         CoseEnumField1 = value1,
///         CoseEnumField2 = value2,
///     }
/// }
#[macro_export]
macro_rules! cose_enum_gen {
    (enum $name:ident {$($field:ident = $field_val:literal),+ $(,)*}) => {
        enum $name {
            $($field = $field_val),+
        }

        impl TryFrom<i64> for $name {
            type Error = hwcryptohal_common::err::HwCryptoError;

            fn try_from(value: i64) -> Result<Self, Self::Error> {
                match value {
                    $(x if x == $name::$field as i64 => Ok($name::$field)),+,
                    _ => Err(hwcrypto_err!(SERIALIZATION_ERROR, "unsupported COSE enum label val {}", value)),
                }
            }
        }

        impl TryFrom<ciborium::value::Integer> for $name {
            type Error = coset::CoseError;

            fn try_from(value: ciborium::value::Integer) -> Result<Self, Self::Error> {
                let value: i64 = value.try_into()?;
                Ok(value.try_into().map_err(|_| coset::CoseError::EncodeFailed)?)
            }
        }
    }
}
