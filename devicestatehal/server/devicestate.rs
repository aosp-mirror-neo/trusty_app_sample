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
use system_state::{ProvisioningAllowedFlagValues, SystemState, SystemStateFlag};

pub struct DeviceState {}

impl binder::Interface for DeviceState {}

impl DeviceState {
    pub(crate) fn new_binder() -> binder::Strong<dyn IDeviceState> {
        BnDeviceState::new_binder(DeviceState {}, binder::BinderFeatures::default())
    }

    /// Retrieves the system state flag controlling provisioning.
    fn get_system_state_provisioning_flag(&self) -> binder::Result<ProvisioningAllowedFlagValues> {
        let to_status = |msg: String| {
            binder::Status::new_exception_str(binder::ExceptionCode::TRANSACTION_FAILED, Some(msg))
        };

        let system_state_session = SystemState::try_connect()
            .map_err(|e| to_status(format!("Failed to connect to system state provider: {e:?}")))?;
        let flag =
            system_state_session.get_flag(SystemStateFlag::ProvisioningAllowed).map_err(|e| {
                to_status(format!("Failed to get ProvisioningAllowed system state flag: {e:?}"))
            })?;
        ProvisioningAllowedFlagValues::try_from(flag).map_err(|e| {
            to_status(format!(
                "Failed to parse ProvisioningAllowed system state flag from value {flag}: {e:?}"
            ))
        })
    }
}

impl IDeviceState for DeviceState {
    fn provisioningAllowed(&self) -> binder::Result<bool> {
        Ok(matches!(
            self.get_system_state_provisioning_flag()?,
            ProvisioningAllowedFlagValues::ProvisioningAllowed
        ))
    }
}
