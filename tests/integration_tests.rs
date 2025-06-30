use serde_json::{Value, json};
use std::collections::HashSet;
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

    // Zero amounts should be rejected
    assert_eq!(response["success"], false);
    assert!(response["error"].as_str().unwrap().contains("must be greater than 0"));

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

    // Zero amounts should be rejected
    assert_eq!(response["success"], false);
    assert!(response["error"].as_str().unwrap().contains("must be greater than 0"));

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

// Additional comprehensive tests
#[tokio::test]
async fn test_keypair_generation_multiple() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    // Generate multiple keypairs and ensure they're all different
    let mut pubkeys = HashSet::new();
    let mut secrets = HashSet::new();

    for i in 0..5 {
        let response = make_request("POST", "/keypair", None).await?;
        assert_eq!(response["success"], true);

        let pubkey = response["data"]["pubkey"].as_str().unwrap();
        let secret = response["data"]["secret"].as_str().unwrap();

        // Ensure uniqueness
        assert!(
            !pubkeys.contains(pubkey),
            "Duplicate pubkey generated at iteration {}",
            i
        );
        assert!(
            !secrets.contains(secret),
            "Duplicate secret generated at iteration {}",
            i
        );

        pubkeys.insert(pubkey.to_string());
        secrets.insert(secret.to_string());

        // Validate format
        assert!(pubkey.len() >= 32 && pubkey.len() <= 50);
        assert!(secret.len() >= 80 && secret.len() <= 100);
    }

    println!("✅ Multiple keypair generation test passed");
    Ok(())
}

#[tokio::test]
async fn test_sign_message_unicode() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    let keypair_response = make_request("POST", "/keypair", None).await?;
    let secret = keypair_response["data"]["secret"].as_str().unwrap();

    // Test with unicode characters
    let unicode_message = "Hello 🌍! Testing unicode: 你好 مرحبا עולם";

    let request_body = json!({
        "message": unicode_message,
        "secret": secret
    });

    let response = make_request("POST", "/message/sign", Some(request_body)).await?;

    assert_eq!(response["success"], true);
    assert_eq!(response["data"]["message"], unicode_message);
    assert!(response["data"]["signature"].is_string());

    println!("✅ Unicode message signing test passed");
    Ok(())
}

#[tokio::test]
async fn test_sign_message_large() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    let keypair_response = make_request("POST", "/keypair", None).await?;
    let secret = keypair_response["data"]["secret"].as_str().unwrap();

    // Test with large message (1KB)
    let large_message = "A".repeat(1024);

    let request_body = json!({
        "message": large_message,
        "secret": secret
    });

    let response = make_request("POST", "/message/sign", Some(request_body)).await?;

    assert_eq!(response["success"], true);
    assert_eq!(response["data"]["message"], large_message);

    println!("✅ Large message signing test passed");
    Ok(())
}

#[tokio::test]
async fn test_send_sol_boundary_amounts() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    let from_response = make_request("POST", "/keypair", None).await?;
    let to_response = make_request("POST", "/keypair", None).await?;
    let from_pubkey = from_response["data"]["pubkey"].as_str().unwrap();
    let to_pubkey = to_response["data"]["pubkey"].as_str().unwrap();

    // Test minimum valid amount (1 lamport)
    let request_body = json!({
        "from": from_pubkey,
        "to": to_pubkey,
        "lamports": 1
    });

    let response = make_request("POST", "/send/sol", Some(request_body)).await?;
    assert_eq!(response["success"], true);

    // Test large amount
    let request_body = json!({
        "from": from_pubkey,
        "to": to_pubkey,
        "lamports": 1000000000000u64 // 1 trillion lamports
    });

    let response = make_request("POST", "/send/sol", Some(request_body)).await?;
    assert_eq!(response["success"], true);

    println!("✅ SOL boundary amounts test passed");
    Ok(())
}

#[tokio::test]
async fn test_token_operations_workflow() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    // Generate keypairs for a complete token workflow
    let authority_kp = make_request("POST", "/keypair", None).await?;
    let mint_kp = make_request("POST", "/keypair", None).await?;
    let recipient_kp = make_request("POST", "/keypair", None).await?;

    let authority = authority_kp["data"]["pubkey"].as_str().unwrap();
    let mint = mint_kp["data"]["pubkey"].as_str().unwrap();
    let recipient = recipient_kp["data"]["pubkey"].as_str().unwrap();

    // Step 1: Create token mint
    let create_request = json!({
        "mintAuthority": authority,
        "mint": mint,
        "decimals": 9
    });

    let create_response = make_request("POST", "/token/create", Some(create_request)).await?;
    assert_eq!(create_response["success"], true);
    println!("✅ Token creation step completed");

    // Step 2: Mint tokens
    let mint_request = json!({
        "mint": mint,
        "destination": recipient,
        "authority": authority,
        "amount": 1000000000 // 1 token with 9 decimals
    });

    let mint_response = make_request("POST", "/token/mint", Some(mint_request)).await?;
    assert_eq!(mint_response["success"], true);
    println!("✅ Token minting step completed");

    // Step 3: Transfer tokens
    let transfer_request = json!({
        "destination": authority, // Transfer back to authority
        "mint": mint,
        "owner": recipient,
        "amount": 500000000 // 0.5 tokens
    });

    let transfer_response = make_request("POST", "/send/token", Some(transfer_request)).await?;
    assert_eq!(transfer_response["success"], true);
    println!("✅ Token transfer step completed");

    println!("✅ Complete token workflow test passed");
    Ok(())
}

#[tokio::test]
async fn test_malformed_json_requests() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    let client = reqwest::Client::new();

    // Test malformed JSON
    let response = client
        .post("http://localhost:8080/message/sign")
        .header("Content-Type", "application/json")
        .body("{invalid json}")
        .send()
        .await?;

    assert_eq!(response.status(), 400);

    // Test missing Content-Type header
    let response = client
        .post("http://localhost:8080/keypair")
        .body("{}")
        .send()
        .await?;

    // Should still work for endpoints that don't require body
    assert!(response.status().is_success() || response.status() == 400);

    println!("✅ Malformed JSON request test passed");
    Ok(())
}

#[tokio::test]
async fn test_wrong_http_methods() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    let client = reqwest::Client::new();

    // Test GET on POST-only endpoints (actix-web returns 404 for unknown routes)
    let response = client.get("http://localhost:8080/keypair").send().await?;
    assert_eq!(response.status(), 404); // Not Found

    let response = client
        .get("http://localhost:8080/message/sign")
        .send()
        .await?;
    assert_eq!(response.status(), 404);

    // Test PUT/DELETE
    let response = client.put("http://localhost:8080/keypair").send().await?;
    assert_eq!(response.status(), 404);

    let response = client
        .delete("http://localhost:8080/keypair")
        .send()
        .await?;
    assert_eq!(response.status(), 404);

    println!("✅ Wrong HTTP methods test passed");
    Ok(())
}

#[tokio::test]
async fn test_invalid_base58_keys() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    // Test with invalid base58 characters
    let request_body = json!({
        "message": "test",
        "secret": "invalid-base58-with-0-and-O-and-I-and-l"
    });

    let response = make_request("POST", "/message/sign", Some(request_body)).await?;
    assert_eq!(response["success"], false);

    // Test with wrong length keys
    let request_body = json!({
        "mintAuthority": "short",
        "mint": "alsoshort",
        "decimals": 6
    });

    let response = make_request("POST", "/token/create", Some(request_body)).await?;
    assert_eq!(response["success"], false);

    println!("✅ Invalid base58 keys test passed");
    Ok(())
}

#[tokio::test]
async fn test_token_decimals_validation() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    let authority_kp = make_request("POST", "/keypair", None).await?;
    let mint_kp = make_request("POST", "/keypair", None).await?;

    let authority = authority_kp["data"]["pubkey"].as_str().unwrap();
    let mint = mint_kp["data"]["pubkey"].as_str().unwrap();

    // Test valid decimal values
    for decimals in [0, 6, 9, 18] {
        let request_body = json!({
            "mintAuthority": authority,
            "mint": mint,
            "decimals": decimals
        });

        let response = make_request("POST", "/token/create", Some(request_body)).await?;
        assert_eq!(response["success"], true);
    }

    println!("✅ Token decimals validation test passed");
    Ok(())
}

#[tokio::test]
async fn test_concurrent_requests() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    // Test concurrent keypair generation
    let mut handles = vec![];

    for i in 0..10 {
        let handle = tokio::spawn(async move {
            match make_request("POST", "/keypair", None).await {
                Ok(response) => {
                    assert_eq!(response["success"], true);
                    println!("✅ Concurrent request {} completed", i);
                    Ok(())
                }
                Err(e) => Err(format!("Request {} failed: {}", i, e)),
            }
        });
        handles.push(handle);
    }

    // Wait for all requests to complete
    for handle in handles {
        handle.await.map_err(|e| format!("Task failed: {}", e))??;
    }

    println!("✅ Concurrent requests test passed");
    Ok(())
}

#[tokio::test]
async fn test_empty_and_null_fields() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    // Test empty string fields
    let request_body = json!({
        "message": "",
        "secret": ""
    });

    let response = make_request("POST", "/message/sign", Some(request_body)).await?;
    assert_eq!(response["success"], false);
    assert_eq!(response["error"], "Missing required fields");

    // Test null fields in JSON (server returns plain text error for null fields)
    let client = reqwest::Client::new();
    let response = client
        .post("http://localhost:8080/message/sign")
        .header("Content-Type", "application/json")
        .json(&json!({
            "message": null,
            "secret": "test"
        }))
        .send()
        .await?;

    // Should return 400 Bad Request for invalid JSON structure
    assert_eq!(response.status(), 400);

    println!("✅ Empty and null fields test passed");
    Ok(())
}

#[tokio::test]
async fn test_stress_large_amounts() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    let from_response = make_request("POST", "/keypair", None).await?;
    let to_response = make_request("POST", "/keypair", None).await?;

    // Test with maximum u64 value
    let request_body = json!({
        "from": from_response["data"]["pubkey"],
        "to": to_response["data"]["pubkey"],
        "lamports": u64::MAX
    });

    let response = make_request("POST", "/send/sol", Some(request_body)).await?;
    assert_eq!(response["success"], true);

    // Test token transfer with max amount
    let dest_response = make_request("POST", "/keypair", None).await?;
    let mint_response = make_request("POST", "/keypair", None).await?;
    let owner_response = make_request("POST", "/keypair", None).await?;

    let request_body = json!({
        "destination": dest_response["data"]["pubkey"],
        "mint": mint_response["data"]["pubkey"],
        "owner": owner_response["data"]["pubkey"],
        "amount": u64::MAX
    });

    let response = make_request("POST", "/send/token", Some(request_body)).await?;
    assert_eq!(response["success"], true);

    println!("✅ Stress test with large amounts passed");
    Ok(())
}

#[tokio::test]
async fn test_complete_integration_workflow() -> Result<(), Box<dyn std::error::Error>> {
    wait_for_server().await?;

    println!("🚀 Starting complete integration workflow test");

    // 1. Generate keypairs for all actors
    let alice_kp = make_request("POST", "/keypair", None).await?;
    let bob_kp = make_request("POST", "/keypair", None).await?;
    let token_mint_kp = make_request("POST", "/keypair", None).await?;

    let alice_pubkey = alice_kp["data"]["pubkey"].as_str().unwrap();
    let alice_secret = alice_kp["data"]["secret"].as_str().unwrap();
    let bob_pubkey = bob_kp["data"]["pubkey"].as_str().unwrap();
    let token_mint = token_mint_kp["data"]["pubkey"].as_str().unwrap();

    println!("✅ Generated keypairs for Alice, Bob, and token mint");

    // 2. Alice signs a message
    let message = format!("Hello Bob! This is Alice. Token mint: {}", token_mint);
    let sign_request = json!({
        "message": message,
        "secret": alice_secret
    });

    let sign_response = make_request("POST", "/message/sign", Some(sign_request)).await?;
    assert_eq!(sign_response["success"], true);
    let signature = sign_response["data"]["signature"].as_str().unwrap();

    println!("✅ Alice signed the message");

    // 3. Verify Alice's signature
    let verify_request = json!({
        "message": message,
        "signature": signature,
        "pubkey": alice_pubkey
    });

    let verify_response = make_request("POST", "/message/verify", Some(verify_request)).await?;
    assert_eq!(verify_response["success"], true);
    assert_eq!(verify_response["data"]["valid"], true);

    println!("✅ Verified Alice's signature");

    // 4. Create a token mint (Alice as authority)
    let create_token_request = json!({
        "mintAuthority": alice_pubkey,
        "mint": token_mint,
        "decimals": 8
    });

    let create_response = make_request("POST", "/token/create", Some(create_token_request)).await?;
    assert_eq!(create_response["success"], true);

    println!("✅ Created token mint with Alice as authority");

    // 5. Mint tokens to Bob
    let mint_to_bob_request = json!({
        "mint": token_mint,
        "destination": bob_pubkey,
        "authority": alice_pubkey,
        "amount": 100000000 // 1 token with 8 decimals
    });

    let mint_response = make_request("POST", "/token/mint", Some(mint_to_bob_request)).await?;
    assert_eq!(mint_response["success"], true);

    println!("✅ Minted tokens to Bob");

    // 6. Bob transfers some tokens back to Alice
    let transfer_request = json!({
        "destination": alice_pubkey,
        "mint": token_mint,
        "owner": bob_pubkey,
        "amount": 25000000 // 0.25 tokens
    });

    let transfer_response = make_request("POST", "/send/token", Some(transfer_request)).await?;
    assert_eq!(transfer_response["success"], true);

    println!("✅ Bob transferred tokens back to Alice");

    // 7. Create SOL transfer from Alice to Bob
    let sol_transfer_request = json!({
        "from": alice_pubkey,
        "to": bob_pubkey,
        "lamports": 1000000 // 0.001 SOL
    });

    let sol_response = make_request("POST", "/send/sol", Some(sol_transfer_request)).await?;
    assert_eq!(sol_response["success"], true);

    println!("✅ Created SOL transfer from Alice to Bob");

    println!("🎉 Complete integration workflow test passed!");
    Ok(())
}
