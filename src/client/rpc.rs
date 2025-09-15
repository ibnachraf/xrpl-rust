use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fmt::Debug, time::Duration};

use crate::client::types::{
    AccountData, AccountInfoParams, AccountInfoParamsResponse, AccountTxInfoParams, PaymentParams, PaymentResponse, SignAndSubmitTransaction, XRPLedgerResponse, XrplRequest, XrplResponse, XrplResponseError
};

pub struct RpcLedgerClientConfig {
    pub url: String,
    pub timeout: Duration,
    pub retry_attempts: u8, // retry_strategy: RetryStrategy???
}

pub struct RpcLedgerClient {
    pub client: Client,
    pub config: RpcLedgerClientConfig,
}

impl RpcLedgerClient {
    pub fn new(config: RpcLedgerClientConfig) -> Self {
        let client = Client::builder().timeout(config.timeout).build().unwrap(); // Handle error appropriately in production code

        RpcLedgerClient { client, config }
    }

    pub async fn send_payment(
        &self,
        payment: &PaymentParams,
    ) -> Result<PaymentResponse, Box<dyn std::error::Error>> {
        let params = SignAndSubmitTransaction {
            tx_json: payment.clone(),
        };

        let result: PaymentResponse = self.call("simulate".to_string(), params).await?;
        Ok(result)
    }

    pub async fn fetch_account_tx_info(
        &self,
        params: &AccountTxInfoParams,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let res: PaymentResponse = self.call("account_tx".to_string(), params).await?;
        Ok(())
    }

    pub async fn get_account_info(
        &self,
        account: String,
    ) -> Result<AccountData, Box<dyn std::error::Error>> {
        let params: AccountInfoParams = AccountInfoParams::default(account);

        let result: AccountInfoParamsResponse =
            self.call("account_info".to_string(), params).await?;
        println!("Account info: {:?}", result);
        Ok(result.account_data)
    }

    async fn call<T, R>(&self, method: String, params: T) -> Result<R, Box<dyn std::error::Error>>
    where
        T: Serialize + Debug,
        R: for<'a> Deserialize<'a> + Debug + XRPLedgerResponse,
    {
        let request_body = XrplRequest {
            method: method.clone(),
            params: vec![params],
        };

        /*println!(
            "Request {}: {}",
            method,
            serde_json::to_string_pretty(&request_body)?
        );*/

        let response = self
            .client
            .post(&self.config.url)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_response: XrplResponseError = response.json().await?;
            println!("Error response: {:?}", error_response.error);
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("HTTP error: {}", error_response.error),
            )));
        }

        let xrpl_response: Value = response.json().await?;
        println!(
            "Raw XRPL response: {}",
            serde_json::to_string_pretty(&xrpl_response)?
        );
        let xrpl_response: XrplResponse<R> = serde_json::from_value(xrpl_response)?;

        if xrpl_response.result.is_error() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("XRPL error: {:?}", xrpl_response),
            )));
        } else {
            println!("XRPL response: {:?}", xrpl_response.result);
            let result = xrpl_response.result;
            return Ok(result);
        }
    }
}
