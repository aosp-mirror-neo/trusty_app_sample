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
use authmgr_be_lib::dice_policy_matching_service_client::get_dice_policy_matching_service;
use authmgr_dice_policy_matching_aidl::aidl::android::trusty::dice::policy::matching::{
    PolicyMatchingResult::PolicyMatchingResult,
};
use binder::SpIBinder;
use hello_world_trusted_aidl::aidl::android::trusty::trustedhal::{
    IHelloWorld::{BnHelloWorld, IHelloWorld},
};
use hello_world_trusted_aidl::binder;
use log::{error, info, trace};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tipc::ClientIdentifier;

// Maximum number of <client_seq_num, policy> entries kept in the memory for testing the policy
// matching service.
const GLOBAL_STATE_MAX_CAPACITY: usize = 10;

pub struct HelloWorldService {
    client_id: ClientIdentifier,
    global_state: Arc<Mutex<HelloWorldGlobalState>>,
}

pub struct HelloWorldGlobalState {
    // Key is the client sequence number, and value is the CBOR-encoded DICE policy.
    pub policy_store: HashMap<i64, Vec<u8>>,
}

impl HelloWorldGlobalState {
    /// Constructor that creates an empty global state
    pub fn new() -> Self {
        HelloWorldGlobalState { policy_store: HashMap::with_capacity(GLOBAL_STATE_MAX_CAPACITY) }
    }

    fn insert_policy(&mut self, client_seq_num: i64, policy: Vec<u8>) -> binder::Result<()> {
        if self.policy_store.len() == GLOBAL_STATE_MAX_CAPACITY {
            error!("Max limit reached for the policy store.");
            return Err(binder_service_specific_error());
        }
        self.policy_store.insert(client_seq_num, policy);
        Ok(())
    }
}

impl binder::Interface for HelloWorldService {}

impl HelloWorldService {
    /// Creates a per-session binder object with client id
    pub fn new_per_session(
        client_id: ClientIdentifier,
        global_state: Arc<Mutex<HelloWorldGlobalState>>,
    ) -> Option<SpIBinder> {
        let hello_service = HelloWorldService { client_id, global_state };
        Some(BnHelloWorld::new_binder(hello_service, binder::BinderFeatures::default()).as_binder())
    }
}

impl IHelloWorld for HelloWorldService {
    fn sayHello(&self, name: &str) -> binder::Result<String> {
        trace!("In IHelloWorld trusted service - sayHello.");
        match self.client_id {
            ClientIdentifier::ClientSeqNumber(n) => {
                info!("sayHello invoked by client with seq num: {n}");
            }
            _ => {
                log::error!("Expected a client seq num, got {:?}", self.client_id);
                return Err(binder_illegal_arg_error());
            }
        }
        let mut hello_string = String::from("Hello ");
        hello_string.push_str(name);
        Ok(hello_string)
    }

    fn sayHelloWithPolicy(
        &self,
        dice_policy: Option<&[u8]>,
    ) -> binder::Result<PolicyMatchingResult> {
        trace!("In IHelloWorld trusted service - sayHelloWithPolicy.");
        let client_seq_num = match self.client_id {
            ClientIdentifier::ClientSeqNumber(n) => {
                info!("sayHelloWithPolicy invoked by client with seq num: {n}");
                n
            }
            _ => {
                log::error!("Expected a client seq num, got {:?}", self.client_id);
                return Err(binder_illegal_arg_error());
            }
        };

        let dice_policy_matching_service = get_dice_policy_matching_service().map_err(|e| {
            error!("Failed to get the dice policy matching service due to: {e:?}.");
            binder_service_specific_error()
        })?;

        // If `dicePolicy` input is not provided AND if this is the fist time the client invokes
        // this method, then call `getPolicy` method of AuthMgr to retrieve this client's latest
        // DICE policy and store it in-memory against the client-seq-number.
        // Return PolicyMatchingResult::SUCCESS upon successful invocation of `getPolicy`.
        //
        // If `dicePolicy` is not provided AND if the client has invoked this method before (i.e.
        // there is an in-memory entry of the client's DICE policy), then call `matchPolicy` method
        // of AuthMgr and return the result returned from that invocation.
        //
        // If `dicePolicy`` is provided, call `matchPolicy` with the provided dice policy and return
        // the result returned from that invocation.
        let mut global_state = self.global_state.lock().unwrap();
        match dice_policy {
            None => {
                if !global_state.policy_store.contains_key(&client_seq_num) {
                    let dice_policy =
                        dice_policy_matching_service.getPolicy(client_seq_num).map_err(|e| {
                            error!("Failed to invoke `getPolicy`: {e:?}");
                            binder_service_specific_error()
                        })?;
                    global_state.insert_policy(client_seq_num, dice_policy.to_vec())?;
                    info!("sayHelloWithPolicy returning success.");
                    Ok(PolicyMatchingResult::SUCCESS)
                } else {
                    // It is safe to unwrap here because we have checked that the policy store
                    // contains the client seq number.
                    let stored_policy = global_state.policy_store.get(&client_seq_num).unwrap();
                    let policy_matching_result = dice_policy_matching_service
                        .matchPolicy(client_seq_num, stored_policy)
                        .map_err(|e| {
                            error!("Failed to invoke `matchPolicy`: {e:?}");
                            binder_service_specific_error()
                        })?;
                    Ok(policy_matching_result)
                }
            }
            Some(dp) => {
                let policy_matching_result =
                    dice_policy_matching_service.matchPolicy(client_seq_num, dp).map_err(|e| {
                        error!("Failed to invoke `matchPolicy`: {e:?}");
                        binder_service_specific_error()
                    })?;
                Ok(policy_matching_result)
            }
        }
    }
}

fn binder_service_specific_error() -> binder::Status {
    binder::Status::new_exception(binder::ExceptionCode::SERVICE_SPECIFIC, None)
}

fn binder_illegal_arg_error() -> binder::Status {
    binder::Status::new_exception(binder::ExceptionCode::ILLEGAL_ARGUMENT, None)
}
