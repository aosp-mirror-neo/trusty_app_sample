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

//! Implementation of IHelloWorld.aidl

use hello_world_trusted_aidl::aidl::android::trusty::trustedhal::IHelloWorld::{
    BnHelloWorld, IHelloWorld,
};
use hello_world_trusted_aidl::binder;
use log::info;

pub struct HelloWorldService;

impl binder::Interface for HelloWorldService {}

impl HelloWorldService {
    /// Creates a binder object
    pub fn new_binder() -> binder::Strong<dyn IHelloWorld> {
        BnHelloWorld::new_binder(HelloWorldService, binder::BinderFeatures::default())
    }
}

impl IHelloWorld for HelloWorldService {
    fn sayHello(&self, name: &str) -> binder::Result<String> {
        info!("In IHelloWorld trusted service...");
        let mut hello_string = String::from("Hello ");
        hello_string.push_str(name);
        Ok(hello_string)
    }
}
