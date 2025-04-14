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

//! FFI declarations.

// Get the bindgen definitions
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(unused)]
#[allow(deref_nullptr)] // https://github.com/rust-lang/rust-bindgen/issues/1651
pub(crate) mod sys {
    include!(env!("BINDGEN_INC_FILE"));
}
