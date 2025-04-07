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

use log::trace;
use service_manager::get_supported_vintf_services;
use vintf_service_info_aidl::aidl::android::vintf::{
    IServiceInfoFetcher::{BnServiceInfoFetcher, IServiceInfoFetcher},
    ServiceInfo::ServiceInfo,
};
use vintf_service_info_aidl::binder;

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
        Ok(services.into_iter().map(|s| s.name().to_string()).collect())
    }

    fn getServiceInfo(&self, service_name: &str) -> binder::Result<ServiceInfo> {
        trace!("In IServiceInfoFetcher get service info... {} ", service_name);
        let service: Vec<&str> = service_name.split('/').collect();
        let service_info = ServiceInfo {
            r#type: service[0].to_string(),
            instance: "default".to_string(),
            version: 1,
            requireVintfDeclaration: true,
            hash: "".to_string(),
            exe: "".to_string(),
            extensions: vec![],
        };
        Ok(service_info)
    }
}
