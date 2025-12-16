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
mod devicestate_vts {
    test::init!();

    use android_hardware_security_see_devicestate::aidl::android::hardware::security::see::devicestate::IDeviceState::IDeviceState;
    use service_manager::wait_for_interface;
    use test::assert_ok;

    const DEVICE_STATE_SERVICE_NAME: &str =
        "android.hardware.security.see.devicestate.IDeviceState/default";

    #[test]
    fn provisioning_allowed_test() {
        let device_state = assert_ok!(
            wait_for_interface::<dyn IDeviceState>(DEVICE_STATE_SERVICE_NAME),
            "Failed to get IDeviceState binder"
        );
        assert_ok!(device_state.provisioningAllowed(), "Failed to get provisioning allowed status");
    }
}
