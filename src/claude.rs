// Cargo.toml dependencies needed:
// [dependencies]
// reqwest = { version = "0.11", features = ["json"] }
// serde = { version = "1.0", features = ["derive"] }
// serde_json = "1.0"
// tokio = { version = "1.0", features = ["full"] }
// thiserror = "1.0"
// hex = "0.4"
// sha2 = "0.10"
// ed25519-dalek = { version = "2.0", features = ["rand_core"] }
// rand = "0.8"
// bs58 = "0.5"

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use ed25519_dalek::{Keypair, Signature, Signer, Verifier, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use sha2::{Sha256, Sha512, Digest};
use rand::rngs::OsRng;

// XRPL-specific error types
#[derive(Error, Debug)]
pub enum XrplError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON serialization/deserialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("XRPL RPC error {error_code}: {error_message}")]
    Rpc { error_code: String, error_message: String },
    #[error("Transaction failed: {0}")]
    Transaction(String),
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error("Invalid secret key: {0}")]
    InvalidSecret(String),
    #[error("Insufficient balance")]
    InsufficientBalance,
    #[error("Trust line not found")]
    TrustLineNotFound,
    #[error("Network error: {0}")]
    Network(String),
    #[error("Signing error: {0}")]
    Signing(String),
}

// XRPL RPC structures
#[derive(Serialize, Debug)]
pub struct XrplRequest<T> {
    pub method: String,
    pub params: Vec<T>,
    pub id: u64,
}

#[derive(Deserialize, Debug)]
pub struct XrplResponse<T> {
    pub result: Option<T>,
    pub error: Option<XrplErrorInfo>,
    pub id: Option<u64>,
}

#[derive(Deserialize, Debug)]
pub struct XrplErrorInfo {
    pub error: String,
    pub error_code: i32,
    pub error_message: String,
}

// XRPL Transaction structures
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Payment {
    #[serde(rename = "TransactionType")]
    pub transaction_type: String,
    #[serde(rename = "Account")]
    pub account: String,
    #[serde(rename = "Destination")]
    pub destination: String,
    #[serde(rename = "Amount")]
    pub amount: Amount,
    #[serde(rename = "Fee")]
    pub fee: String,
    #[serde(rename = "Flags")]
    pub flags: u32,
    #[serde(rename = "Sequence")]
    pub sequence: u32,
    #[serde(rename = "DestinationTag", skip_serializing_if = "Option::is_none")]
    pub destination_tag: Option<u32>,
    #[serde(rename = "LastLedgerSequence", skip_serializing_if = "Option::is_none")]
    pub last_ledger_sequence: Option<u32>,
    #[serde(rename = "Memos", skip_serializing_if = "Option::is_none")]
    pub memos: Option<Vec<Memo>>,
    #[serde(rename = "SigningPubKey", skip_serializing_if = "Option::is_none")]
    pub signing_pub_key: Option<String>,
    #[serde(rename = "TxnSignature", skip_serializing_if = "Option::is_none")]
    pub txn_signature: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Amount {
    Drops(String), // XRP in drops
    IssuedCurrency {
        currency: String,
        value: String,
        issuer: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Memo {
    #[serde(rename = "Memo")]
    pub memo: MemoData,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemoData {
    #[serde(rename = "MemoData", skip_serializing_if = "Option::is_none")]
    pub memo_data: Option<String>,
}

// Account info structures
#[derive(Deserialize, Debug)]
pub struct AccountInfo {
    #[serde(rename = "Account")]
    pub account: String,
    #[serde(rename = "Balance")]
    pub balance: String,
    #[serde(rename = "Sequence")]
    pub sequence: u32,
}

#[derive(Deserialize, Debug)]
pub struct AccountInfoResult {
    pub account_data: AccountInfo,
    pub validated: bool,
}

// Trust line structures
#[derive(Deserialize, Debug)]
pub struct TrustLine {
    pub account: String,
    pub balance: String,
    pub currency: String,
    pub limit: String,
    pub limit_peer: String,
    pub no_ripple: Option<bool>,
    pub no_ripple_peer: Option<bool>,
    pub quality_in: Option<u32>,
    pub quality_out: Option<u32>,
}

#[derive(Deserialize, Debug)]
pub struct AccountLinesResult {
    pub account: String,
    pub lines: Vec<TrustLine>,
}

// Submit result
#[derive(Deserialize, Debug)]
pub struct SubmitResult {
    pub engine_result: String,
    pub engine_result_code: i32,
    pub engine_result_message: String,
    pub tx_blob: String,
    pub tx_json: Payment,
}

// Server info for getting current ledger
#[derive(Deserialize, Debug)]
pub struct ServerInfo {
    pub info: ServerInfoData,
}

#[derive(Deserialize, Debug)]
pub struct ServerInfoData {
    pub validated_ledger: ValidatedLedger,
}

#[derive(Deserialize, Debug)]
pub struct ValidatedLedger {
    pub seq: u32,
}

// XRPL Client
pub struct XrplClient {
    client: Client,
    server_url: String,
    request_id: std::sync::atomic::AtomicU64,
}

impl XrplClient {
    pub fn new_testnet() -> Result<Self, XrplError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            server_url: "https://s.altnet.rippletest.net:51234".to_string(),
            request_id: std::sync::atomic::AtomicU64::new(0),
        })
    }

    async fn call<T, R>(&self, method: &str, params: T) -> Result<R, XrplError>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let id = self.request_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let request = XrplRequest {
            method: method.to_string(),
            params: vec![params],
            id,
        };

        let response = self
            .client
            .post(&self.server_url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(XrplError::Network(format!(
                "HTTP {}: {}",
                response.status(),
                response.status().canonical_reason().unwrap_or("Unknown error")
            )));
        }

        let json_response: serde_json::Value = response.json().await?;
        let xrpl_response: XrplResponse<R> = serde_json::from_value(json_response)?;

        if let Some(error) = xrpl_response.error {
            return Err(XrplError::Rpc {
                error_code: error.error,
                error_message: error.error_message,
            });
        }

        xrpl_response.result.ok_or_else(|| {
            XrplError::Network("No result in response".to_string())
        })
    }

    pub async fn get_account_info(&self, account: &str) -> Result<AccountInfoResult, XrplError> {
        #[derive(Serialize)]
        struct AccountInfoParams {
            account: String,
            ledger_index: String,
        }

        self.call(
            "account_info",
            AccountInfoParams {
                account: account.to_string(),
                ledger_index: "current".to_string(),
            },
        )
        .await
    }

    pub async fn get_account_lines(&self, account: &str) -> Result<AccountLinesResult, XrplError> {
        #[derive(Serialize)]
        struct AccountLinesParams {
            account: String,
            ledger_index: String,
        }

        self.call(
            "account_lines",
            AccountLinesParams {
                account: account.to_string(),
                ledger_index: "current".to_string(),
            },
        )
        .await
    }

    pub async fn get_server_info(&self) -> Result<ServerInfo, XrplError> {
        #[derive(Serialize)]
        struct EmptyParams {}

        self.call("server_info", EmptyParams {}).await
    }

    pub async fn submit_transaction(&self, tx_blob: &str) -> Result<SubmitResult, XrplError> {
        #[derive(Serialize)]
        struct SubmitParams {
            tx_blob: String,
        }

        self.call(
            "submit",
            SubmitParams {
                tx_blob: tx_blob.to_string(),
            },
        )
        .await
    }
}

// Cryptographic utilities
pub struct XrplCrypto;

impl XrplCrypto {
    // Convert secret key to keypair
    pub fn secret_to_keypair(secret: &str) -> Result<Keypair, XrplError> {
        // Remove 's' prefix if present and decode from base58
        let secret_clean = if secret.starts_with('s') {
            &secret[1..]
        } else {
            secret
        };

        let decoded = bs58::decode(secret_clean)
            .into_vec()
            .map_err(|_| XrplError::InvalidSecret("Invalid base58 encoding".to_string()))?;

        if decoded.len() < 32 {
            return Err(XrplError::InvalidSecret("Secret too short".to_string()));
        }

        // Take first 32 bytes as seed
        let seed = &decoded[0..32];
        
        // Generate keypair from seed using SHA512
        let mut hasher = Sha512::new();
        hasher.update(seed);
        hasher.update(&[0u8, 0u8, 0u8, 0u8]); // Account sequence
        let hash = hasher.finalize();
        
        let secret_key = ed25519_dalek::SecretKey::from_bytes(&hash[..32])
            .map_err(|e| XrplError::InvalidSecret(format!("Invalid secret key: {}", e)))?;
        
        let public_key = ed25519_dalek::PublicKey::from(&secret_key);
        
        Ok(Keypair {
            secret: secret_key,
            public: public_key,
        })
    }

    // Get XRPL address from public key
    pub fn public_key_to_address(public_key: &ed25519_dalek::PublicKey) -> String {
        let mut hasher = Sha256::new();
        hasher.update([0xED]); // ED25519 prefix
        hasher.update(public_key.as_bytes());
        let hash = hasher.finalize();

        // RIPEMD160 would be used here in real implementation
        // For simplicity, we'll use a placeholder
        let account_id = &hash[0..20];
        
        // Add checksum and encode
        let mut payload = Vec::new();
        payload.push(0x00); // Account prefix
        payload.extend_from_slice(account_id);
        
        let checksum = {
            let mut hasher = Sha256::new();
            hasher.update(&payload);
            let hash1 = hasher.finalize();
            let mut hasher = Sha256::new();
            hasher.update(hash1);
            hasher.finalize()
        };
        
        payload.extend_from_slice(&checksum[0..4]);
        
        format!("r{}", bs58::encode(payload).into_string())
    }

    // Sign transaction
    pub fn sign_transaction(tx: &Payment, keypair: &Keypair) -> Result<String, XrplError> {
        // Serialize transaction for signing (simplified)
        let tx_json = serde_json::to_string(tx)
            .map_err(|e| XrplError::Signing(format!("Serialization error: {}", e)))?;
        
        // In real implementation, this would use XRPL's specific serialization format
        let signature = keypair.sign(tx_json.as_bytes());
        
        // Create signed transaction blob (simplified)
        let mut signed_tx = tx.clone();
        signed_tx.signing_pub_key = Some(hex::encode(keypair.public.as_bytes()));
        signed_tx.txn_signature = Some(hex::encode(signature.to_bytes()));
        
        // Convert to hex blob (simplified)
        let blob = serde_json::to_string(&signed_tx)
            .map_err(|e| XrplError::Signing(format!("Blob creation error: {}", e)))?;
        
        Ok(hex::encode(blob))
    }
}

// Main function to send tokens
pub async fn send_token(
    user1_secret: &str,
    user2_address: &str,
    issuer_address: &str,
    currency_code: &str,
    amount: &str,
) -> Result<String, XrplError> {
    // Initialize client
    let client = XrplClient::new_testnet()?;
    
    // Get keypair from secret
    let keypair = XrplCrypto::secret_to_keypair(user1_secret)?;
    let user1_address = XrplCrypto::public_key_to_address(&keypair.public);
    
    println!("User1 address: {}", user1_address);
    println!("Sending {} {} to {}", amount, currency_code, user2_address);
    
    // Validate addresses
    if !user2_address.starts_with('r') || user2_address.len() < 25 {
        return Err(XrplError::InvalidAddress(user2_address.to_string()));
    }
    
    if !issuer_address.starts_with('r') || issuer_address.len() < 25 {
        return Err(XrplError::InvalidAddress(issuer_address.to_string()));
    }
    
    // Get account info for sequence number
    let account_info = client.get_account_info(&user1_address).await?;
    println!("User1 sequence: {}", account_info.account_data.sequence);
    
    // Check if user has trust line for the token
    let account_lines = client.get_account_lines(&user1_address).await?;
    let trust_line = account_lines.lines.iter().find(|line| {
        line.currency == currency_code && line.account == *issuer_address
    });
    
    if trust_line.is_none() {
        return Err(XrplError::TrustLineNotFound);
    }
    
    let trust_line = trust_line.unwrap();
    println!("Current token balance: {}", trust_line.balance);
    
    // Verify sufficient balance
    let current_balance: f64 = trust_line.balance.parse()
        .map_err(|_| XrplError::Network("Invalid balance format".to_string()))?;
    let send_amount: f64 = amount.parse()
        .map_err(|_| XrplError::Network("Invalid amount format".to_string()))?;
    
    if current_balance < send_amount {
        return Err(XrplError::InsufficientBalance);
    }
    
    // Get current ledger for LastLedgerSequence
    let server_info = client.get_server_info().await?;
    let current_ledger = server_info.info.validated_ledger.seq;
    
    // Create payment transaction
    let payment = Payment {
        transaction_type: "Payment".to_string(),
        account: user1_address.clone(),
        destination: user2_address.to_string(),
        amount: Amount::IssuedCurrency {
            currency: currency_code.to_string(),
            value: amount.to_string(),
            issuer: issuer_address.to_string(),
        },
        fee: "12".to_string(), // 12 drops fee
        flags: 0x80000000, // tfFullyCanonicalSig
        sequence: account_info.account_data.sequence,
        destination_tag: None,
        last_ledger_sequence: Some(current_ledger + 10), // Valid for 10 ledgers
        memos: None,
        signing_pub_key: None,
        txn_signature: None,
    };
    
    println!("Prepared payment transaction");
    
    // Sign the transaction
    let signed_blob = XrplCrypto::sign_transaction(&payment, &keypair)?;
    println!("Transaction signed");
    
    // Submit transaction
    let result = client.submit_transaction(&signed_blob).await?;
    
    if result.engine_result == "tesSUCCESS" {
        println!("✅ Transaction successful!");
        println!("Transaction hash: {:?}", result.tx_json);
        Ok(result.engine_result)
    } else {
        Err(XrplError::Transaction(format!(
            "{}: {}",
            result.engine_result, result.engine_result_message
        )))
    }
}

// Helper function to create trust line (if needed)
pub async fn create_trust_line(
    user_secret: &str,
    issuer_address: &str,
    currency_code: &str,
    limit: &str,
) -> Result<String, XrplError> {
    let client = XrplClient::new_testnet()?;
    let keypair = XrplCrypto::secret_to_keypair(user_secret)?;
    let user_address = XrplCrypto::public_key_to_address(&keypair.public);
    
    // Get account info
    let account_info = client.get_account_info(&user_address).await?;
    
    // Create TrustSet transaction
    #[derive(Serialize, Clone)]
    struct TrustSet {
        #[serde(rename = "TransactionType")]
        transaction_type: String,
        #[serde(rename = "Account")]
        account: String,
        #[serde(rename = "LimitAmount")]
        limit_amount: Amount,
        #[serde(rename = "Fee")]
        fee: String,
        #[serde(rename = "Flags")]
        flags: u32,
        #[serde(rename = "Sequence")]
        sequence: u32,
    }
    
    let trust_set = TrustSet {
        transaction_type: "TrustSet".to_string(),
        account: user_address,
        limit_amount: Amount::IssuedCurrency {
            currency: currency_code.to_string(),
            value: limit.to_string(),
            issuer: issuer_address.to_string(),
        },
        fee: "12".to_string(),
        flags: 0x80000000,
        sequence: account_info.account_data.sequence,
    };
    
    // Note: This is simplified - you would need proper signing for TrustSet
    println!("Trust line transaction prepared: {:?}", trust_set);
    
    Ok("Trust line creation prepared (signing implementation needed)".to_string())
}

// Usage example
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 XRPL Token Transfer Client");
    
    // Example parameters (these would be provided by the user)
    let user1_secret = "sEdV2Qa5K5GGM9xMqBLYcNJ8RjBzFsH"; // Example secret
    let user2_address = "rDNDTG7PjNNRe2Jv5nZHRWM2K8sVNx4x"; // Example address
    let issuer_address = "rN7n7otQDd6FczFgLdSqtcsAUxDkw6fzRH"; // Example issuer
    let currency_code = "USD";
    let amount = "10.0";
    
    println!("Attempting to send token...");
    
    // This would fail without valid secrets and addresses
    match send_token(
        user1_secret,
        user2_address,
        issuer_address,
        currency_code,
        amount,
    ).await {
        Ok(result) => {
            println!("✅ Token sent successfully: {}", result);
        }
        Err(e) => {
            println!("❌ Error sending token: {:?}", e);
        }
    }
    
    println!("\n📋 Function usage:");
    println!("send_token(user1_secret, user2_address, issuer_address, currency_code, amount)");
    println!("  - user1_secret: Secret key of sender (base58 encoded)");
    println!("  - user2_address: XRPL address of recipient");
    println!("  - issuer_address: XRPL address of token issuer");
    println!("  - currency_code: 3-letter currency code (e.g., 'USD')");
    println!("  - amount: Amount to send as string (e.g., '10.0')");
    
    Ok(())
}