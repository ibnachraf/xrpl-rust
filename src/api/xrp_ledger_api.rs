//Private Key: "4bc7d70ead3f361cde210509b5ab2c6d00000000000000000000000000000000"
//Public Key: "3c2ef7d2a24448449a3c09c4ba946768aa80b5254fd0fdb24cb062c03185ff4a"
//Address: rH9oNTBqsSR55T4z68D49SwTzj7ygFimfK

use crate::api::utils::derive_classic_address_from_seed;
use crate::client::rpc::*;
use crate::client::types::*;
use std::time::Duration;

const XRP_LEDGER_TESTNET: &str = "https://testnet.xrpl-labs.com/";

pub struct XRPLedgerAPI {
    pub client: RpcLedgerClient,
}

impl XRPLedgerAPI {
    pub async fn offer(
        &self,
        user1_secret: &str,
        user2_address: &str,
        issuer_address: &str,
        currency_code: &str,
        amount: &str,
    ) -> Result<PaymentResponse, Box<dyn std::error::Error>> {
        // Address: rUCTNFrXiLcNVk21gtqyYdpBekLMPJfXbA
        // Secret: sEdVnmBGUpU8ceSKi8NAKDUWPRKJL57

        let user_address = derive_classic_address_from_seed(user1_secret).unwrap();

        let account_info: AccountData = self
            .client
            .get_account_info(String::from(user_address.clone()))
            .await
            .unwrap();

        let amount: IssuedCurrency = IssuedCurrency {
            currency: String::from(currency_code),
            value: String::from(amount),
            issuer: String::from(issuer_address),
        };

        let payment = PaymentParams {
            transaction_type: "Payment".to_string(),
            account: user_address.clone(),
            destination: user2_address.to_string(),
            amount: amount,
            fee: "12".to_string(), // TODO: Estimate fee from server
            sequence: account_info.sequence,
        };

        let send_payment_result = self
            .client
            .send_payment("simulate".to_string(), &payment)
            .await;

        send_payment_result
    }
}

#[tokio::test]
async fn test_xrp_ledger_api() {
    let config = RpcLedgerClientConfig {
        url: XRP_LEDGER_TESTNET.to_string(),
        timeout: Duration::from_secs(10),
        retry_attempts: 3,
    };

    let client = RpcLedgerClient::new(config);

    let user1_seed = "sn3nxiW7v8KXzPzAqzyHXbSSKNuN9";
    let user2_address = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
    // Let send USD

    let currency = "USD";
    let amount = "1";
    let issuer_address = "rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn";

    let api = XRPLedgerAPI { client: client };

    let result = api
        .offer(user1_seed, user2_address, issuer_address, currency, amount)
        .await;
    assert!(result.is_ok());
    if let Ok(result_ok) = result {
        assert!(result_ok.is_success());
        assert!(result_ok.tx_json["Amount"]["currency"].as_str() == Some(currency));
        assert!(result_ok.tx_json["Amount"]["issuer"].as_str() == Some(issuer_address));
        assert!(result_ok.tx_json["Amount"]["value"].as_str() == Some(amount));
        assert!(result_ok.tx_json["hash"].as_str().is_some())
    }
}
