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

use crate::service_info_fetcher::ServiceInfoFetcher;

use alloc::rc::Rc;
use log::info;
use rpcbinder::RpcServer;
use tipc::{service_dispatcher, wrap_service, Manager, PortCfg, TipcError};

const SERVICE_INFO_FETCHER_PORT_NAME: &str = "com.android.trusty.vintf";

wrap_service!(DirectTestService(RpcServer: UnbufferedService));

service_dispatcher! {
    enum VintfServices {
        DirectTestService,
    }
}

pub fn main_loop() -> Result<(), TipcError> {
    info!("Hello from Vintf TA!");
    let service = ServiceInfoFetcher::new_binder();
    let direct_rpc_server = RpcServer::new_per_session(move |_uuid| Some(service.as_binder()));
    let direct = DirectTestService(direct_rpc_server);

    let cfg = PortCfg::new(SERVICE_INFO_FETCHER_PORT_NAME)
        .expect("failed to create port config")
        .allow_ta_connect()
        .allow_ns_connect();

    let mut dispatcher = VintfServices::<1>::new().expect("dispatcher creation failed");
    dispatcher
        .add_service(Rc::new(direct), cfg)
        .expect("failed to add direct ServiceInfoFetcher to dispatcher");
    Manager::<_, _, 1, 1>::new_with_dispatcher(dispatcher, [])
        .expect("Manager could not be created")
        .run_event_loop()
}
