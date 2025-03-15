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
#![allow(dead_code)]
//! Implementation of ITrustedServicesCommonsConnect.aidl
use crate::server::HELLO_WORLD_TRUSTED_SERVICE_PORT;
use authmgr_handover_aidl::aidl::android::trusty::handover::ITrustedServicesHandover::{
    BnTrustedServicesHandover, ITrustedServicesHandover,
};
use authmgr_handover_aidl::binder;
use binder::{ParcelFileDescriptor, SpIBinder};
use log::error;
use rpcbinder::RpcServer;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Weak};
use tipc::raw::{HandleSetWrapper, ToConnect, WorkToDo};
use tipc::{Handle, PortCfg, Uuid};
use trusty_std::ffi::CString;

pub struct HandoverService {
    handle_set: Weak<HandleSetWrapper<RpcServer>>,
    trusted_service: Arc<RpcServer>,
    // TODO b/401776482. This is temporary, until the bug is fixed.
    uuid: Uuid,
}

impl binder::Interface for HandoverService {}

impl HandoverService {
    pub fn new_handover_session(
        uuid: Uuid,
        // Handleset is a weak reference to avoid potential cyclic references
        handle_set: Weak<HandleSetWrapper<RpcServer>>,
        trusted_service: Arc<RpcServer>,
    ) -> Option<SpIBinder> {
        let handover_service = HandoverService { handle_set, trusted_service, uuid };
        Some(
            BnTrustedServicesHandover::new_binder(
                handover_service,
                binder::BinderFeatures::default(),
            )
            .as_binder(),
        )
    }
}

impl ITrustedServicesHandover for HandoverService {
    fn handoverConnection(
        &self,
        fd: &ParcelFileDescriptor,
        _client_seq_num: i32,
    ) -> binder::Result<()> {
        let raw_fd = fd.as_raw_fd();
        let handle = Handle::from_raw(raw_fd).map_err(|e| {
            error!("Failed to create the handle from the raw fd: {:?}.", e);
            binder::Status::new_exception(
                binder::ExceptionCode::SERVICE_SPECIFIC,
                Some(
                    &CString::new("Could not create the handle from the raw fd.".to_string())
                        .unwrap(),
                ),
            )
        })?;
        let dup_handle = handle.try_clone().map_err(|e| {
            error!("Failed to clone the handle: {:?}", e);
            binder::Status::new_exception(
                binder::ExceptionCode::SERVICE_SPECIFIC,
                Some(&CString::new("Failed to clone the handle.".to_string()).unwrap()),
            )
        })?;
        // Prevent the destructor of the handle from calling because it will be closed by the Parcel
        // File Descriptor which owns it.
        core::mem::forget(handle);
        let hello_service_port_cfg = PortCfg::new_raw(HELLO_WORLD_TRUSTED_SERVICE_PORT.into())
            .allow_ta_connect()
            .allow_ns_connect();
        let to_connect = ToConnect::new(
            dup_handle,
            Arc::clone(&self.trusted_service),
            hello_service_port_cfg,
            // TODO b/401776482. We need to pass in `client_seq_num` once the bug is fixed.
            self.uuid.clone(),
        );
        self.handle_set
            .upgrade()
            .ok_or(binder::Status::new_exception(
                binder::ExceptionCode::SERVICE_SPECIFIC,
                Some(&CString::new("Failed to get the handle set.".to_string()).unwrap()),
            ))?
            .add_work(WorkToDo::Connect(to_connect));
        Ok(())
    }
}
