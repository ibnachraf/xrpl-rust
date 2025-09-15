# XRPL Rust API

This project provides a Rust interface for interacting with the XRP Ledger (XRPL), including account management and payment operations.

## Code Structure

Key Files

- api/utils.rs:
Contains cryptographic utilities, base58 encoding/decoding, and address derivation logic.

- xrp_ledger_api.rs: 
Implements the XRPLedgerAPI struct, which provides async methods for sending payments and offers. Includes integration tests using #[tokio::test].

- client/rpc.rs: 
Defines RpcLedgerClient, which handles HTTP requests to XRPL endpoints.

- client/types.rs:
Contains Rust structs for XRPL concepts like AccountData, IssuedCurrency, PaymentParams, and response types.

### Example Usage
The integration test in xrp_ledger_api.rs demonstrates how to:

- Configure the RPC client
- Derive addresses from seeds
- Send a payment using the XRPL API

### Note:
This structure separates concerns between cryptography/utilities, API logic, and network communication, making the codebase modular and maintainable.