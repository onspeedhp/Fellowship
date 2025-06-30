use serde_json::{Value, json};
use std::time::Duration;
use tokio::time::sleep;

// Test client for making HTTP requests
async fn make_request(
    method: &str,
    endpoint: &str,
    body: Option<Value>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let url = format!("http://localhost:8080{}", endpoint);

    let mut request = match method {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        _ => panic!("Unsupported HTTP method: {}", method),
    };

    request = request.header("Content-Type", "application/json");

    if let Some(json_body) = body {
        request = request.json(&json_body);
    }

    let response = request.send().await?;
    let json: Value = response.json().await?;
    Ok(json)
}

// Helper function to check if server is running
async fn wait_for_server() -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..30 {
        // Wait up to 30 seconds
        if let Ok(_) = make_request("POST", "/keypair", None).await {
            return Ok(());
        }
        sleep(Duration::from_secs(1)).await;
    }
    Err("Server did not start in time".into())
}

#[tokio::test]
async fn test_keypair_generation() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    let response = make_request("POST", "/keypair", None).await?;

    // Check response structure
    assert_eq!(response["success"], true);
    assert!(response["data"]["pubkey"].is_string());
    assert!(response["data"]["secret"].is_string());

    // Check that pubkey and secret are base58 strings of correct length
    let pubkey = response["data"]["pubkey"].as_str().unwrap();
    let secret = response["data"]["secret"].as_str().unwrap();

    assert!(!pubkey.is_empty());
    assert!(!secret.is_empty());
    assert!(pubkey.len() >= 32); // Base58 pubkey should be around 44 chars
    assert!(secret.len() >= 80); // Base58 secret key should be around 88 chars

    println!("✅ Keypair generation test passed");
    Ok(())
}

#[tokio::test]
async fn test_create_token_success() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    // First generate a keypair to use
    let keypair_response = make_request("POST", "/keypair", None).await?;
    let pubkey = keypair_response["data"]["pubkey"].as_str().unwrap();

    // Generate another keypair for mint address
    let mint_keypair_response = make_request("POST", "/keypair", None).await?;
    let mint_pubkey = mint_keypair_response["data"]["pubkey"].as_str().unwrap();

    let request_body = json!({
        "mintAuthority": pubkey,
        "mint": mint_pubkey,
        "decimals": 6
    });

    let response = make_request("POST", "/token/create", Some(request_body)).await?;

    // Check response structure
    assert_eq!(response["success"], true);
    assert!(response["data"]["program_id"].is_string());
    assert!(response["data"]["accounts"].is_array());
    assert!(response["data"]["instruction_data"].is_string());

    println!("✅ Create token test passed");
    Ok(())
}

#[tokio::test]
async fn test_create_token_invalid_pubkey() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    let request_body = json!({
        "mintAuthority": "invalid-pubkey",
        "mint": "invalid-mint",
        "decimals": 6
    });

    let response = make_request("POST", "/token/create", Some(request_body)).await?;

    // Check error response
    assert_eq!(response["success"], false);
    assert!(response["error"].is_string());

    println!("✅ Create token invalid pubkey test passed");
    Ok(())
}

#[tokio::test]
async fn test_mint_token_success() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    // Generate keypairs for mint, destination, and authority
    let mint_response = make_request("POST", "/keypair", None).await?;
    let dest_response = make_request("POST", "/keypair", None).await?;
    let auth_response = make_request("POST", "/keypair", None).await?;

    let request_body = json!({
        "mint": mint_response["data"]["pubkey"],
        "destination": dest_response["data"]["pubkey"],
        "authority": auth_response["data"]["pubkey"],
        "amount": 1000000
    });

    let response = make_request("POST", "/token/mint", Some(request_body)).await?;

    // Check response structure
    assert_eq!(response["success"], true);
    assert!(response["data"]["program_id"].is_string());
    assert!(response["data"]["accounts"].is_array());
    assert!(response["data"]["instruction_data"].is_string());

    println!("✅ Mint token test passed");
    Ok(())
}

#[tokio::test]
async fn test_sign_message_success() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    // Generate a keypair first
    let keypair_response = make_request("POST", "/keypair", None).await?;
    let secret = keypair_response["data"]["secret"].as_str().unwrap();
    let expected_pubkey = keypair_response["data"]["pubkey"].as_str().unwrap();

    let request_body = json!({
        "message": "Hello, Solana!",
        "secret": secret
    });

    let response = make_request("POST", "/message/sign", Some(request_body)).await?;

    // Check response structure
    assert_eq!(response["success"], true);
    assert!(response["data"]["signature"].is_string());
    assert_eq!(response["data"]["public_key"], expected_pubkey);
    assert_eq!(response["data"]["message"], "Hello, Solana!");

    // Check that signature is a valid base64 string
    let signature = response["data"]["signature"].as_str().unwrap();
    assert!(!signature.is_empty());

    println!("✅ Sign message test passed");
    Ok(())
}

#[tokio::test]
async fn test_sign_message_missing_fields() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    let request_body = json!({
        "message": "",
        "secret": "invalid-secret"
    });

    let response = make_request("POST", "/message/sign", Some(request_body)).await?;

    // Check error response
    assert_eq!(response["success"], false);
    assert_eq!(response["error"], "Missing required fields");

    println!("✅ Sign message missing fields test passed");
    Ok(())
}

#[tokio::test]
async fn test_verify_message_success() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    // First sign a message
    let keypair_response = make_request("POST", "/keypair", None).await?;
    let secret = keypair_response["data"]["secret"].as_str().unwrap();
    let pubkey = keypair_response["data"]["pubkey"].as_str().unwrap();

    let sign_body = json!({
        "message": "Hello, Solana!",
        "secret": secret
    });

    let sign_response = make_request("POST", "/message/sign", Some(sign_body)).await?;
    let signature = sign_response["data"]["signature"].as_str().unwrap();

    // Now verify the signature
    let verify_body = json!({
        "message": "Hello, Solana!",
        "signature": signature,
        "pubkey": pubkey
    });

    let response = make_request("POST", "/message/verify", Some(verify_body)).await?;

    // Check response structure
    assert_eq!(response["success"], true);
    assert_eq!(response["data"]["valid"], true);
    assert_eq!(response["data"]["message"], "Hello, Solana!");
    assert_eq!(response["data"]["pubkey"], pubkey);

    println!("✅ Verify message success test passed");
    Ok(())
}

#[tokio::test]
async fn test_verify_message_invalid_signature() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    let keypair_response = make_request("POST", "/keypair", None).await?;
    let pubkey = keypair_response["data"]["pubkey"].as_str().unwrap();

    let verify_body = json!({
        "message": "Hello, Solana!",
        "signature": "aW52YWxpZCBzaWduYXR1cmU=", // Invalid base64 signature
        "pubkey": pubkey
    });

    let response = make_request("POST", "/message/verify", Some(verify_body)).await?;

    // Should return error for invalid signature format
    assert_eq!(response["success"], false);
    assert!(response["error"].is_string());

    println!("✅ Verify message invalid signature test passed");
    Ok(())
}

#[tokio::test]
async fn test_send_sol_success() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    // Generate keypairs for from and to addresses
    let from_response = make_request("POST", "/keypair", None).await?;
    let to_response = make_request("POST", "/keypair", None).await?;

    let request_body = json!({
        "from": from_response["data"]["pubkey"],
        "to": to_response["data"]["pubkey"],
        "lamports": 100000
    });

    let response = make_request("POST", "/send/sol", Some(request_body)).await?;

    // Check response structure
    assert_eq!(response["success"], true);
    assert!(response["data"]["program_id"].is_string());
    assert!(response["data"]["accounts"].is_array());
    assert!(response["data"]["instruction_data"].is_string());

    // Check that we have the expected number of accounts (from and to)
    let accounts = response["data"]["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 2);

    println!("✅ Send SOL test passed");
    Ok(())
}

#[tokio::test]
async fn test_send_sol_zero_amount() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    let from_response = make_request("POST", "/keypair", None).await?;
    let to_response = make_request("POST", "/keypair", None).await?;

    let request_body = json!({
        "from": from_response["data"]["pubkey"],
        "to": to_response["data"]["pubkey"],
        "lamports": 0
    });

    let response = make_request("POST", "/send/sol", Some(request_body)).await?;

    // Check error response
    assert_eq!(response["success"], false);
    assert_eq!(response["error"], "Invalid amount: must be greater than 0");

    println!("✅ Send SOL zero amount test passed");
    Ok(())
}

#[tokio::test]
async fn test_send_token_success() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    // Generate keypairs for destination, mint, and owner
    let dest_response = make_request("POST", "/keypair", None).await?;
    let mint_response = make_request("POST", "/keypair", None).await?;
    let owner_response = make_request("POST", "/keypair", None).await?;

    let request_body = json!({
        "destination": dest_response["data"]["pubkey"],
        "mint": mint_response["data"]["pubkey"],
        "owner": owner_response["data"]["pubkey"],
        "amount": 100000
    });

    let response = make_request("POST", "/send/token", Some(request_body)).await?;

    // Check response structure
    assert_eq!(response["success"], true);
    assert!(response["data"]["program_id"].is_string());
    assert!(response["data"]["accounts"].is_array());
    assert!(response["data"]["instruction_data"].is_string());

    println!("✅ Send token test passed");
    Ok(())
}

#[tokio::test]
async fn test_send_token_zero_amount() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    let dest_response = make_request("POST", "/keypair", None).await?;
    let mint_response = make_request("POST", "/keypair", None).await?;
    let owner_response = make_request("POST", "/keypair", None).await?;

    let request_body = json!({
        "destination": dest_response["data"]["pubkey"],
        "mint": mint_response["data"]["pubkey"],
        "owner": owner_response["data"]["pubkey"],
        "amount": 0
    });

    let response = make_request("POST", "/send/token", Some(request_body)).await?;

    // Check error response
    assert_eq!(response["success"], false);
    assert_eq!(response["error"], "Invalid amount: must be greater than 0");

    println!("✅ Send token zero amount test passed");
    Ok(())
}

#[tokio::test]
async fn test_message_sign_verify_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    // Generate a keypair
    let keypair_response = make_request("POST", "/keypair", None).await?;
    let secret = keypair_response["data"]["secret"].as_str().unwrap();
    let pubkey = keypair_response["data"]["pubkey"].as_str().unwrap();

    let test_message = "This is a test message for roundtrip verification!";

    // Sign the message
    let sign_body = json!({
        "message": test_message,
        "secret": secret
    });

    let sign_response = make_request("POST", "/message/sign", Some(sign_body)).await?;
    assert_eq!(sign_response["success"], true);

    let signature = sign_response["data"]["signature"].as_str().unwrap();

    // Verify the signature
    let verify_body = json!({
        "message": test_message,
        "signature": signature,
        "pubkey": pubkey
    });

    let verify_response = make_request("POST", "/message/verify", Some(verify_body)).await?;
    assert_eq!(verify_response["success"], true);
    assert_eq!(verify_response["data"]["valid"], true);

    // Test with wrong message (should fail verification)
    let wrong_verify_body = json!({
        "message": "Wrong message",
        "signature": signature,
        "pubkey": pubkey
    });

    let wrong_verify_response =
        make_request("POST", "/message/verify", Some(wrong_verify_body)).await?;
    assert_eq!(wrong_verify_response["success"], true);
    assert_eq!(wrong_verify_response["data"]["valid"], false);

    println!("✅ Message sign/verify roundtrip test passed");
    Ok(())
}
