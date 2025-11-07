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

#[cfg(test)]
mod tests {
    test::init!();

    use android_hardware_security_see_devicestate::aidl::android::hardware::security::see::devicestate::IDeviceState::IDeviceState;
    use service_manager::wait_for_interface;
    use system_state::{ProvisioningAllowedFlagValues, SystemState, SystemStateFlag};
    use test::expect_eq;

    const DEVICE_STATE_SERVICE_NAME: &str =
        "android.hardware.security.see.devicestate.IDeviceState/default";

    #[test]
    fn provisioning_allowed_test() {
        let device_state = wait_for_interface::<dyn IDeviceState>(DEVICE_STATE_SERVICE_NAME)
            .expect("Failed to get IDeviceState binder");
        let is_provisioning_allowed =
            device_state.provisioningAllowed().expect("Failed to get provisioning allowed status");

        let system_state_session =
            SystemState::try_connect().expect("Failed to get SystemState service");
        let flag = system_state_session
            .get_flag(SystemStateFlag::ProvisioningAllowed)
            .expect("Failed to get ProvisioningAllowed system state flag");
        let system_state_flag = ProvisioningAllowedFlagValues::try_from(flag)
            .expect("Failed to parse ProvisioningAllowed system state flag");

        expect_eq!(
            is_provisioning_allowed,
            matches!(system_state_flag, ProvisioningAllowedFlagValues::ProvisioningAllowed)
        );
    }
}
