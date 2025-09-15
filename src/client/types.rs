use ripple_keypairs::{PrivateKey, Seed};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json, ser};

#[derive(Serialize, Debug)]
pub struct XrplRequest<T> {
    pub method: String,
    pub params: Vec<T>,
}

#[derive(Deserialize, Debug)]
pub struct XrplResponse<T: XRPLedgerResponse> {
    pub result: T,
}

#[derive(Deserialize)]
pub struct XrplResponseError {
    pub error: String,
}

#[derive(Serialize, Debug)]
pub struct Sign {
    offline: bool,
    api_version: u32,
    secret: String,
    tx_json: Value,
}

#[derive(Serialize, Debug)]
pub struct SignAndSubmitTransaction {
    //pub secret: String,
    pub tx_json: PaymentParams,
}

#[derive(Deserialize, Debug)]
pub struct SignResponse {
    pub tx_blob: String,
    pub tx_json: Value,
}

pub trait XRPLedgerResponse {
    fn is_success(&self) -> bool;
    fn is_error(&self) -> bool;
}

impl XRPLedgerResponse for SignResponse {
    fn is_success(&self) -> bool {
        true
    }

    fn is_error(&self) -> bool {
        false
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct PaymentParams {
    // TODO: #[serde(rename_all = "PascalCase")]
    #[serde(rename = "TransactionType")]
    pub transaction_type: String,
    #[serde(rename = "Account")]
    pub account: String,
    #[serde(rename = "Destination")]
    pub destination: String,
    #[serde(rename = "Amount")]
    pub amount: IssuedCurrency,
    #[serde(rename = "Fee")]
    pub fee: String,
    #[serde(rename = "Sequence")]
    pub sequence: u32,
}

#[derive(Serialize, Debug, Clone)]
pub struct IssuedCurrency {
    pub currency: String,
    pub value: String,
    pub issuer: String,
}

#[derive(Deserialize, Debug)]
pub struct PaymentResponse {
    //https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/transaction-methods/simulate#response-format
    pub status: String,
    pub tx_json: Value,
}

impl XRPLedgerResponse for PaymentResponse {
    fn is_success(&self) -> bool {
        self.status == "success"
    }

    fn is_error(&self) -> bool {
        self.status != "success"
    }
}

#[derive(Serialize, Debug)]
pub struct AccountInfoParams {
    account: String,
    ledger_index: String,
    queue: bool,
}

impl AccountInfoParams {
    pub fn default(account: String) -> Self {
        AccountInfoParams {
            account: account,
            ledger_index: "current".to_string(),
            queue: true,
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct AccountData {
    #[serde(rename = "Account")]
    pub account: String,
    #[serde(rename = "Balance")]
    pub balance: String,
    #[serde(rename = "Sequence")]
    pub sequence: u32,
}

#[derive(Serialize, Debug)]
pub struct SignedTransaction {
    pub tx_blob: String,
}

#[derive(Deserialize, Debug)]
pub struct AccountInfoParamsResponse {
    pub account_data: AccountData,
    status: String,
}

impl XRPLedgerResponse for AccountInfoParamsResponse {
    fn is_success(&self) -> bool {
        self.status == "success"
    }

    fn is_error(&self) -> bool {
        self.status != "success"
    }
}

pub struct AccountInfo {
    pub account: String,
    pub balance: String,
    pub sequence: u32,
}

pub enum Error {
    InvalidData(String),
}

#[derive(Serialize, Debug)]
pub struct AccountTxInfoParams {
    pub account: String,
    pub binary: bool,
    pub forward: bool,
    pub ledger_index_min: i32,
    pub ledger_index_max: i32,
    pub limit: i32,
}
