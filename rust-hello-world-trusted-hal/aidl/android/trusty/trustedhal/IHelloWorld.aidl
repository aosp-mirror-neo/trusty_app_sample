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

package android.trusty.trustedhal;
import android.trusty.dice.policy.matching.PolicyMatchingResult;

/**
 * This is an example service to demonstrate how to implement a Trusted HAL service to be compliant
 * with the AuthMgr protocol.
 */
interface IHelloWorld {
    /**
     * Simply returns the string: "Hello " + name.
     */
    String sayHello(in String name);

    /**
     * This method is for testing the policy matching service of AuthMgr.
     * Behavior:
     * 1. If dicePolicy is not provided AND if this is the first time the client invokes this method,
     *    then call `getPolicy` method of AuthMgr to retrieve this client's latest DICE policy and
     *    store it in-memory against the client-seq-number. Return PolicyMatchingResult::SUCCESS
     *    upon successful invocation of `getPolicy`.
     *
     * 2. If dicePolicy is not provided AND if the client has invoked this method before (i.e.
     *    there is an in-memory entry of the client's DICE policy), then call `matchPolicy` method
     *    of AuthMgr and return the result returned from that invocation.
     *
     * 3. If dicePolicy is provided, call `matchPolicy` method of AuthMgr along with the provided
     *    dicePolicy and return the result returned from that invocation.
     */
    PolicyMatchingResult sayHelloWithPolicy(in @nullable byte[] dicePolicy);
}