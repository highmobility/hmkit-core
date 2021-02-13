# HMKit Core

HMKit Core implements the transportation protocol of HMKit in pure C. It is used in libraries such as the Android SDK and Python SDK and can also be used in embedded environments. The protocol supports both connectivity through Telematics and Bluetooth Low Energy.

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
