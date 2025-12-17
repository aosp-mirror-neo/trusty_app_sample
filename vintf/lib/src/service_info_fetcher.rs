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

//! Implementation of IServiceInfoFetcher.aidl

use log::{error, trace};
use service_manager::{get_supported_vintf_services, get_vintf_binder};
use vintf_service_info_aidl::aidl::android::vintf::{
    IServiceInfoFetcher::{BnServiceInfoFetcher, IServiceInfoFetcher},
    ServiceInfo::ServiceInfo,
    StabilityLevel::StabilityLevel,
};
use vintf_service_info_aidl::binder::{
    self,
    binder_impl::{Deserialize, IBinderInternal, TransactionCode, LAST_CALL_TRANSACTION},
    SpIBinder,
};

const INTERFACE_HASH_TRANSACTION: TransactionCode = LAST_CALL_TRANSACTION - 1;
const INTERFACE_VERSION_TRANSACTION: TransactionCode = LAST_CALL_TRANSACTION;

pub struct ServiceInfoFetcher;

impl binder::Interface for ServiceInfoFetcher {}

impl ServiceInfoFetcher {
    /// Creates a binder object
    pub fn new_binder() -> binder::Strong<dyn IServiceInfoFetcher> {
        BnServiceInfoFetcher::new_binder(ServiceInfoFetcher, binder::BinderFeatures::default())
    }
}

impl IServiceInfoFetcher for ServiceInfoFetcher {
    fn listAllServices(&self) -> binder::Result<Vec<String>> {
        trace!("In IServiceInfoFetcher list service...");
        let services = get_supported_vintf_services();
        Ok(services.into_iter().map(|s| s.to_string()).collect())
    }

    fn getServiceInfo(&self, service_name: &str) -> binder::Result<ServiceInfo> {
        trace!("In IServiceInfoFetcher get service info... {} ", service_name);
        let mut service_binder = get_vintf_binder(service_name)?;
        let interface = service_binder.get_class().ok_or_else(|| {
            binder::Status::new_service_specific_error_str(-1, Some("failed to get interface"))
        })?;
        let descriptor = interface.get_descriptor();
        let name: Vec<&str> = service_name.split('/').collect();
        if name.len() != 2 {
            return Err(binder::Status::new_service_specific_error_str(
                -1,
                Some("invalid service name"),
            ));
        }
        if name[0] != descriptor {
            return Err(binder::Status::new_service_specific_error_str(
                -1,
                Some("service name does not match descriptor"),
            ));
        }
        let hash = transact(&service_binder, INTERFACE_HASH_TRANSACTION)?;
        let version = transact(&service_binder, INTERFACE_VERSION_TRANSACTION)?;
        let service_info = ServiceInfo {
            r#type: descriptor,
            instance: name[1].to_string(),
            version,
            requireVintfDeclaration: service_binder.requires_vintf_declaration(),
            hash,
            exe: "".to_string(),
            extensions: vec![],
            binderLibDefaultStability: get_binder_lib_stability_level(&mut service_binder),
        };
        Ok(service_info)
    }
}

fn get_binder_lib_stability_level(b: &mut SpIBinder) -> StabilityLevel {
    let ext = b.get_extension().unwrap_or_else(|e| {
        error!("failed to get extension: {e:?}");
        None
    });

    match ext {
        None => StabilityLevel::UNKNOWN,
        Some(ext) => {
            if ext.is_vendor_stable() {
                StabilityLevel::VENDOR
            } else if ext.is_system_stable() {
                StabilityLevel::SYSTEM
            } else if ext.requires_vintf_declaration() {
                StabilityLevel::VINTF
            } else {
                StabilityLevel::UNKNOWN
            }
        }
    }
}

fn transact<D: Deserialize + Default>(
    b: &SpIBinder,
    transaction_code: TransactionCode,
) -> binder::Result<D> {
    let data = b.prepare_transact()?;
    let parcel = match b.submit_transact(transaction_code, data, 0) {
        Ok(p) => p,
        // UNKNOWN_TRANSACTION means the HAL doesn't implement this transaction.
        // In this case, returning a default value as in the host HAL vintf VTS.
        Err(binder::StatusCode::UNKNOWN_TRANSACTION) => return Ok(D::default()),
        Err(e) => return Err(e.into()),
    };
    let status: binder::Status =
        parcel.read().inspect_err(|e| error!("failed to read binder status: {e:?}"))?;
    if status.is_ok() {
        Ok(parcel.read().inspect_err(|e| error!("failed to read parcel: {e:?}"))?)
    } else {
        error!("failed to get parcel: {status:?}");
        Err(status)
    }
}
