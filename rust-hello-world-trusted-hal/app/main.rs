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

//! Entrypoint to the HelloWorld Trusted HAL TA

use hello_world_trusted_lib::server::main_loop;
use log::debug;

fn log_formatter(record: &log::Record) -> String {
    // line number should be present, so keeping it simple by just returning a 0.
    let line = record.line().unwrap_or(0);
    let file = record.file().unwrap_or("unknown file");
    format!("{}: {}:{} {}\n", record.level(), file, line, record.args())
}

fn main() {
    let config = trusty_log::TrustyLoggerConfig::default()
        .with_min_level(log::Level::Info)
        .format(&log_formatter);
    trusty_log::init_with_config(config);
    debug!("starting Hello World Trusted HAL...");
    main_loop().expect("Hello World Trusted HAL TA quits unexpectedly.");
}
