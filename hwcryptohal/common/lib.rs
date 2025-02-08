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

//! Library implementing common client and server HWCrypto functionality.

mod android;
pub mod err;
pub mod policy;
pub use android::{AES_SYMMETRIC_KEY_USES_MASK, HMAC_KEY_USES_MASK};

// Trusty Rust unittests use a sligthly different setup and environment than
// normal Rust unittests. The next call adds the necessary variables and code to be
// able to compile this library as a Trusty unittest TA.
#[cfg(test)]
mod tests {
    test::init!();
}
