// Copyright 2025, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Trusty VINTF TA

use log::info;
use vintf_ta_server::server::main_loop;

fn main() {
    let config = trusty_log::TrustyLoggerConfig::default();
    trusty_log::init_with_config(config);
    info!("starting Vintf TA...");
    main_loop().expect("Vintf TA quits unexpectedly.");
}
