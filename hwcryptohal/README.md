# HwCrypto HAL
This repository contains a software implementation of the HwCrypto HAL.
## Repository structure
* **aidl/rust/** - Build files to compile the HWCrypto AIDL interfaces for Trusty.
* **common/** - Code that can be reused outside of the TA
* **server/** - Trusted Application (TA) code
* **server/app/** - Platform dependent code that sets up a Trusty Trusted App serving the different
hwcrypto interfaces.
* **server/interfaces/** - Definitions of the different traits that each platform needs to implement to be
able to port the TA to their OS.
* **server/platform/** - Trusty implementation of the traits defined under **server/interfaces/**
## Porting to a device
To port to a new device, provide a new implementation of all the interfaces under
**server/interfaces/** (please see the **Platform dependent interfaces** section for more
details about each interface) on a crate called `hwcryptohalplatform` and provide a wrapper that
serves all the HwCrypto services (please see **HwCrypto Services** section for more details about
the services)
## Platform dependent interfaces
### ClientIdentification
This interface provides functionality needed to authorize and identify HwCrypto HAL clients. All
functions on this interface have a parameter called `client_id`, which is the ID provided when
creating a new `HwCryptoKey` object, which should be able to uniquely identify a client. Its
definition can be found under
[server/interfaces/client_identification.rs](server/interfaces/client_identification.rs) and a
Trusty implementation is provided under
[server/platform/client_identification.rs](server/platform/client_identification.rs).
### DeviceKeys
This interface provides functionality needed to work with keys that are tied to the device. Its
definition can be found under
[server/interfaces/device_keys.rs](server/interfaces/device_keys.rs) and a Trusty implementation is
provided under [server/platform/device_keys.rs](server/platform/device_keys.rs).
### MemoryMappedObject
This interface provides the functionality needed to map and access memory pointed by a binder
`ParcelFileDescriptor`. Its definition can be found under
[server/interfaces/memory_access.rs](server/interfaces/memory_access.rs) an a Trusty implementation
is provided under [server/platform/memory.rs](server/platform/memory.rs).
### TestHelpers
This interface proviodes functionality to be used on the HwCrypto HAL unit tests. Its definition can
be found under [server/interfaces/test.rs](server/interfaces/test.rs) and a Trusty implementation
is provided under [server/platform/test_helpers.rs](server/platform/test_helpers.rs).
### DeviceTime
This interface provides access to time related functions. Its definition can be found under
[server/interfaces/time.rs](server/interfaces/time.rs) and a Trusty implementation is provided under
[server/platform/time.rs](server/platform/time.rs)
### Cryptography Traits
In addition to the traits define on HwCrypto HAL, the implementor must provide an implementation of
the following KeyMint Traits: `Aes`, `Hmac` and `Rng`, which the platform crate shall reimport as
`AesImpl`, `HmacImpl` and `RngImpl`.
## HwCrypto Services
The platform implementation must also provide a wrapper that creates the HwCrypto HAL server. This
wrapper shall provide ports to connect to the following services:
### IHwCryptoKey
This is the main IHwCrypto service defined on [this AIDL](https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/see/hwcrypto/aidl/android/hardware/security/see/hwcrypto/IHwCryptoKey.aidl).
This service is provided for direct connections from other trusted components and to create one the
server implementation should create a `HwCryptoKey` binder object that shall manage all calls to this
HAL.
### ITrustedServicesHandover
This service is used to interface with the AuthMgr to receive authenticated client connections.
After the handover the connections should be handled by a `HwCryptoKey` binder object.
### ISharedSecret
This [AIDL service](https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/sharedsecret/aidl/android/hardware/security/sharedsecret/ISharedSecret.aidl)
is provided when KeyMint is running outside of the Trusted Execution Environment.In this case the
shared KeyMint HMAC key is calculated by HwCrypto and provided to the KeyMint instance running
outside of the Trusted Execution Environment. For this the common TA code provides the
`SharedSecret` binder object.