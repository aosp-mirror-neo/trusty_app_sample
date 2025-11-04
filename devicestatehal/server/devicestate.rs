/*
 * Copyright (C) 2025 The Android Open Source Project
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

//! Implementation of the `IDeviceState` AIDL interface.

use android_hardware_security_see_devicestate::aidl::android::hardware::security::see::devicestate::IDeviceState::{
    BnDeviceState, IDeviceState,
};
use android_hardware_security_see_devicestate::binder;

pub struct DeviceState {}

impl binder::Interface for DeviceState {}

impl DeviceState {
    pub(crate) fn new_binder() -> binder::Strong<dyn IDeviceState> {
        BnDeviceState::new_binder(DeviceState {}, binder::BinderFeatures::default())
    }
}

impl IDeviceState for DeviceState {
    fn provisioningAllowed(&self) -> binder::Result<bool> {
        // TODO(b/454389557): Add actual logic for provisioningAllowed.
        Ok(true)
    }
}
