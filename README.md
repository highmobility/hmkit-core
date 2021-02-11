# HMKit Core

HMKit Core implements the transportation protocol of HMKit in pure C. It is used in libraries such as the Android SDK and Python SDK and can also be used in embedded environments. The protocol supports both connectivity through Telematics and Bluetooth Low Energy.

# Table of contents

* [Architecture](#features)
* [Requirements](#requirements)
* [Getting Started](#getting-started)
* [Contributing](#contributing)
* [Licence](#Licence)

## Architecture

**General**: Core is a pure C library that contains the HMKit protocol and flow implementations. Every connection point is handled by an abstraction layer or with a callback function.

**hmkit_core_api_callback**: This contains all callback functions that will forward Core events to the upper layer.

**hmkit_core_api**: This contains commands that the upper layer can call to trigger actions.

**hmkit_core_bt_crypto_hal**: This is the lower level abstraction layer for cryptography libraries or target hardware.

**hmkit_core_bt_debug_hal**: This is the lower level abstraction layer for debug output.

**hmkit_core_persistence_hal**: This is the lower level abstraction layer for persistence storage. Can be some database, embedded flash or something else that will keep the data after a power cycle.

**hmkit_core_connectivity_hal**: This is the lower level abstraction layer for Bluetooth and network connectivity.

## Requirements

HMKit Core is pure C code that follow C99.

## Getting Started

Get started with HMKIT Core [📘 browse the wiki](https://github.com/highmobility/hmkit-core/wiki).

## Contributing

Before starting please read our contribution rules [📘 Contributing](CONTRIBUTE.md)

### Developing

For development we use the system_test directory. It is a car and a phone example application with moc Bluetooth. 

1. Go to directory system_test
2. Compile tests with make
3. Run test ./systemtest

### Running Unit Tests

Unit tests are light weight pure C tests that will go through protocols and flows with hard-coded example data.

1. Go to directory unit_test
2. Compile tests with make
3. Run tests ./hmservice

## Licence
This repository is using MIT licence. See more in [📘 LICENCE](LICENCE.md)
