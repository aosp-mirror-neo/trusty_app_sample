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

#[cfg(test)]
mod hwcryptokey_vts;

#[cfg(test)]
mod tests {
    test::init!();

    use hwcrypto_thal::{HwCryptoKey, Result};
    use service_manager::wait_for_interface;
    const RUST_HWCRYPTO_SERVICE: &str =
        "android.hardware.security.see.hwcrypto.IHwCryptoKey/default";

    pub(crate) fn get_hwcryptokey() -> Result<HwCryptoKey> {
        Ok(HwCryptoKey::new(wait_for_interface(RUST_HWCRYPTO_SERVICE)?))
    }
}
