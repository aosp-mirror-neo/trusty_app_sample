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

//! Module providing access to platform specific functions used by the library.
use kmr_common::crypto;

#[derive(Default)]
pub struct PlatformRng;

impl crypto::Rng for PlatformRng {
    fn add_entropy(&mut self, _data: &[u8]) {
        // BoringSSL manages its own entropy; manual reseeding is a no-op here.
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        openssl::rand::rand_bytes(dest)
            .expect("shouldn't happen, function never fails on BoringSSL");
    }
}
