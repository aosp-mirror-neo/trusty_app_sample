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

//! COSE/CBOR helper functions and macros

/// Macro helper to wrap an AIDL enum and provide conversion implementations for it. It could
/// potentially be re-written using a procedural derive macro, but using a macro_rules for now for
/// simplicity.
/// It provides conversion helpers from u64 and from Ciborium::Integer types and should have the
/// following form:
///
/// aidl_enum_wrapper! {
///     aidl_name: AidlEnumName,
///     wrapper_name: NewRustEnumName,
///     fields: [AIDL_FIELD_1, AIDL_FIELD_2,...]
/// }
///
#[macro_export]
macro_rules! aidl_enum_wrapper {
    (aidl_name: $aidl_name:ident, wrapper_name: $wrapper_name:ident, fields: [$($field:ident),+ $(,)*]$(,)?) => {
        #[derive(Debug, Copy, Clone, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $wrapper_name(pub $aidl_name);

        impl From<$wrapper_name> for $aidl_name {
            fn from(value: $wrapper_name) -> Self {
                value.0
            }
        }

        impl From<$aidl_name> for $wrapper_name {
            fn from(value: $aidl_name) -> Self {
                $wrapper_name(value)
            }
        }

        impl TryFrom<u64> for $wrapper_name {
            type Error = $crate::err::HwCryptoError;

            fn try_from(value: u64) -> Result<Self, Self::Error> {
                let val = match value {
                    $(x if x == $aidl_name::$field.0 as u64 =>Ok($aidl_name::$field)),+,
                    _ => Err($crate::hwcrypto_err!(SERIALIZATION_ERROR, "unsupported enum val {}", value)),
                }?;
                Ok($wrapper_name(val))
            }
        }

        impl TryFrom<ciborium::value::Integer> for $wrapper_name {
            type Error = coset::CoseError;

            fn try_from(value: ciborium::value::Integer) -> Result<Self, Self::Error> {
                let value: u64 = value.try_into()?;
                Ok(value.try_into().map_err(|_| coset::CoseError::EncodeFailed)?)
            }
        }

        impl From<$wrapper_name> for ciborium::value::Integer {
            fn from(value: $wrapper_name) -> Self {
                (value.0.0 as u64).into()
            }
        }
    }
}

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
            type Error = $crate::err::HwCryptoError;

            fn try_from(value: i64) -> Result<Self, Self::Error> {
                match value {
                    $(x if x == $name::$field as i64 => Ok($name::$field)),+,
                    _ => Err($crate::hwcrypto_err!(SERIALIZATION_ERROR, "unsupported COSE enum label val {}", value)),
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
