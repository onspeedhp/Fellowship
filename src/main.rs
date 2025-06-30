use actix_web::{
    App, Error, HttpResponse, HttpServer, Result, dev::ServiceRequest, dev::ServiceResponse,
    dev::Transform, middleware::Logger, web,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use futures_util::future::LocalBoxFuture;
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
};
use spl_token::instruction::{initialize_mint, mint_to, transfer};
use std::fmt;
use std::str::FromStr;

// Custom blockchain transaction error handler
#[derive(Debug)]
struct SolanaTransactionError(String);

impl fmt::Display for SolanaTransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl std::error::Error for SolanaTransactionError {}

impl actix_web::error::ResponseError for SolanaTransactionError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::BadRequest().json(ApiResponse::<()>::error(self.0.clone()))
    }
}

// Standard response structures
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(response_payload: T) -> Self {
        ApiResponse {
            success: true,
            data: Some(response_payload),
            error: None,
        }
    }

    fn error(error_description: String) -> Self {
        ApiResponse {
            success: false,
            data: None,
            error: Some(error_description),
        }
    }
}

// Request/Response structures
#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize, Debug)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize, Debug)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize, Debug)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize, Debug)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Deserialize, Debug)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize, Debug)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct TokenInstructionResponse {
    program_id: String,
    accounts: Vec<TokenAccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SolTransferResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct TokenAccountInfo {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

// Advanced request monitoring middleware
struct BlockchainRequestMonitor;

impl<S, B> Transform<S, ServiceRequest> for BlockchainRequestMonitor
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = BlockchainRequestProcessor<S>;
    type Future = std::future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        std::future::ready(Ok(BlockchainRequestProcessor { service }))
    }
}

struct BlockchainRequestProcessor<S> {
    service: S,
}

impl<S, B> actix_web::dev::Service<ServiceRequest> for BlockchainRequestProcessor<S>
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, incoming_request: ServiceRequest) -> Self::Future {
        println!(
            "Incoming Request: {} {}",
            incoming_request.method(),
            incoming_request.path()
        );
        println!("Headers: {:?}", incoming_request.headers());

        // Extract and log request body for POST requests
        let http_method = incoming_request.method().clone();
        let request_path = incoming_request.path().to_string();

        if http_method == "POST" {
            let content_type_header = incoming_request
                .headers()
                .get("content-type")
                .and_then(|header_value| header_value.to_str().ok())
                .unwrap_or("");

            if content_type_header.contains("application/json") {
                // For JSON requests, we'll log what we can from headers
                println!("Content-Type: {}", content_type_header);
                if let Some(payload_length) = incoming_request.headers().get("content-length") {
                    println!("Content-Length: {:?}", payload_length);
                }
            }
        }

        let service_future = self.service.call(incoming_request);
        Box::pin(async move {
            let response_result = service_future.await?;
            println!(
                "Response Status: {} for {} {}",
                response_result.status(),
                http_method,
                request_path
            );
            Ok(response_result)
        })
    }
}

// Solana address validation utilities
fn validate_solana_public_key(address_string: &str) -> Result<Pubkey, SolanaTransactionError> {
    if address_string.trim().is_empty() {
        return Err(SolanaTransactionError(
            "Public key cannot be empty".to_string(),
        ));
    }
    Pubkey::from_str(address_string.trim())
        .map_err(|_| SolanaTransactionError("Invalid public key format".to_string()))
}

fn decode_and_validate_keypair(secret_key_string: &str) -> Result<Keypair, SolanaTransactionError> {
    if secret_key_string.trim().is_empty() {
        return Err(SolanaTransactionError(
            "Secret key cannot be empty".to_string(),
        ));
    }

    let decoded_bytes = bs58::decode(secret_key_string.trim())
        .into_vec()
        .map_err(|_| SolanaTransactionError("Invalid base58 secret key format".to_string()))?;

    if decoded_bytes.len() != 64 {
        return Err(SolanaTransactionError(
            "Invalid secret key length".to_string(),
        ));
    }

    Keypair::from_bytes(&decoded_bytes)
        .map_err(|_| SolanaTransactionError("Invalid keypair format".to_string()))
}

fn verify_token_transfer_amount(transfer_amount: u64) -> Result<(), SolanaTransactionError> {
    if transfer_amount == 0 {
        return Err(SolanaTransactionError(
            "Amount must be greater than 0".to_string(),
        ));
    }
    if transfer_amount > u64::MAX / 2 {
        return Err(SolanaTransactionError(
            "Amount exceeds maximum allowed value".to_string(),
        ));
    }
    Ok(())
}

// Endpoint handlers
async fn generate_keypair() -> Result<HttpResponse> {
    let new_keypair = Keypair::new();
    let public_key_string = new_keypair.pubkey().to_string();
    let encoded_secret_key = bs58::encode(new_keypair.to_bytes()).into_string();

    let keypair_response = ApiResponse::success(KeypairResponse {
        pubkey: public_key_string,
        secret: encoded_secret_key,
    });
    Ok(HttpResponse::Ok().json(keypair_response))
}

async fn create_token(
    token_creation_request: web::Json<CreateTokenRequest>,
) -> Result<HttpResponse> {
    println!("POST /token/create body: {:?}", token_creation_request);

    // Validate all required fields
    if token_creation_request.mint_authority.trim().is_empty()
        || token_creation_request.mint.trim().is_empty()
    {
        return Err(SolanaTransactionError("Missing required fields".to_string()).into());
    }

    // Validate decimals
    if token_creation_request.decimals > 9 {
        return Err(SolanaTransactionError("Decimals must be between 0 and 9".to_string()).into());
    }

    // Parse and validate public keys
    let mint_authority_pubkey = validate_solana_public_key(&token_creation_request.mint_authority)?;
    let mint_address_pubkey = validate_solana_public_key(&token_creation_request.mint)?;

    // Create the instruction
    let mint_initialization_instruction = initialize_mint(
        &spl_token::id(),
        &mint_address_pubkey,
        &mint_authority_pubkey,
        Some(&mint_authority_pubkey),
        token_creation_request.decimals,
    )
    .map_err(|initialization_error| {
        SolanaTransactionError(format!(
            "Failed to create mint instruction: {}",
            initialization_error
        ))
    })?;

    let instruction_accounts: Vec<AccountInfo> = mint_initialization_instruction
        .accounts
        .iter()
        .map(|account_meta| AccountInfo {
            pubkey: account_meta.pubkey.to_string(),
            is_signer: account_meta.is_signer,
            is_writable: account_meta.is_writable,
        })
        .collect();

    let instruction_response_data = InstructionResponse {
        program_id: mint_initialization_instruction.program_id.to_string(),
        accounts: instruction_accounts,
        instruction_data: BASE64.encode(&mint_initialization_instruction.data),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(instruction_response_data)))
}

async fn mint_token(token_minting_request: web::Json<MintTokenRequest>) -> Result<HttpResponse> {
    println!("POST /token/mint body: {:?}", token_minting_request);

    // Validate amount first
    verify_token_transfer_amount(token_minting_request.amount)?;

    // Validate all required fields
    if token_minting_request.mint.trim().is_empty()
        || token_minting_request.destination.trim().is_empty()
        || token_minting_request.authority.trim().is_empty()
    {
        return Err(SolanaTransactionError("Missing required fields".to_string()).into());
    }

    // Parse and validate all public keys first
    let token_mint_pubkey = validate_solana_public_key(&token_minting_request.mint)?;
    let destination_owner_pubkey = validate_solana_public_key(&token_minting_request.destination)?;
    let minting_authority_pubkey = validate_solana_public_key(&token_minting_request.authority)?;

    // Get the destination ATA
    let destination_associated_token_account =
        spl_associated_token_account::get_associated_token_address(
            &destination_owner_pubkey,
            &token_mint_pubkey,
        );

    // Create the instruction
    let token_minting_instruction = mint_to(
        &spl_token::id(),
        &token_mint_pubkey,
        &destination_associated_token_account,
        &minting_authority_pubkey,
        &[],
        token_minting_request.amount,
    )
    .map_err(|mint_error| {
        SolanaTransactionError(format!("Failed to create mint instruction: {}", mint_error))
    })?;

    let minting_instruction_accounts: Vec<AccountInfo> = token_minting_instruction
        .accounts
        .iter()
        .map(|account_meta| AccountInfo {
            pubkey: account_meta.pubkey.to_string(),
            is_signer: account_meta.is_signer,
            is_writable: account_meta.is_writable,
        })
        .collect();

    let minting_response_data = InstructionResponse {
        program_id: token_minting_instruction.program_id.to_string(),
        accounts: minting_instruction_accounts,
        instruction_data: BASE64.encode(&token_minting_instruction.data),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(minting_response_data)))
}

async fn sign_message(
    message_signing_request: web::Json<SignMessageRequest>,
) -> Result<HttpResponse> {
    println!("POST /message/sign body: {:?}", message_signing_request);
    if message_signing_request.message.is_empty() || message_signing_request.secret.is_empty() {
        let error_response = ApiResponse::<()>::error("Missing required fields".to_string());
        return Ok(HttpResponse::BadRequest().json(error_response));
    }

    match decode_and_validate_keypair(&message_signing_request.secret) {
        Ok(signing_keypair) => {
            let message_bytes_to_sign = message_signing_request.message.as_bytes();
            let generated_signature = signing_keypair.sign_message(message_bytes_to_sign);

            let signature_response_data = SignMessageResponse {
                signature: BASE64.encode(generated_signature.as_ref()),
                public_key: signing_keypair.pubkey().to_string(),
                message: message_signing_request.message.clone(),
            };

            let successful_response = ApiResponse::success(signature_response_data);
            Ok(HttpResponse::Ok().json(successful_response))
        }
        Err(keypair_error) => {
            let error_response = ApiResponse::<()>::error(keypair_error.0);
            Ok(HttpResponse::BadRequest().json(error_response))
        }
    }
}

async fn verify_message(
    signature_verification_request: web::Json<VerifyMessageRequest>,
) -> Result<HttpResponse> {
    // Validate all required fields
    if signature_verification_request.message.trim().is_empty()
        || signature_verification_request.signature.trim().is_empty()
        || signature_verification_request.pubkey.trim().is_empty()
    {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            "Missing required fields".to_string(),
        )));
    }

    // Parse public key first
    let signer_public_key = match validate_solana_public_key(&signature_verification_request.pubkey)
    {
        Ok(parsed_pubkey) => parsed_pubkey,
        Err(pubkey_error) => {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(pubkey_error.0)));
        }
    };

    // Decode and validate signature
    let decoded_signature_bytes =
        match BASE64.decode(signature_verification_request.signature.trim()) {
            Ok(signature_bytes) => signature_bytes,
            Err(_) => {
                return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                    "Invalid base64 signature format".to_string(),
                )));
            }
        };

    let signature_object = match Signature::try_from(decoded_signature_bytes.as_slice()) {
        Ok(signature) => signature,
        Err(_) => {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                "Invalid signature format".to_string(),
            )));
        }
    };

    let original_message_bytes = signature_verification_request.message.as_bytes();
    let signature_is_valid =
        signature_object.verify(&signer_public_key.to_bytes(), original_message_bytes);

    let verification_result = VerifyMessageResponse {
        valid: signature_is_valid,
        message: signature_verification_request.message.clone(),
        pubkey: signature_verification_request.pubkey.clone(),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(verification_result)))
}

async fn send_sol(sol_transfer_request: web::Json<SendSolRequest>) -> Result<HttpResponse> {
    if sol_transfer_request.lamports == 0 {
        let insufficient_amount_response =
            ApiResponse::<()>::error("Invalid amount: must be greater than 0".to_string());
        return Ok(HttpResponse::BadRequest().json(insufficient_amount_response));
    }

    match (
        validate_solana_public_key(&sol_transfer_request.from),
        validate_solana_public_key(&sol_transfer_request.to),
    ) {
        (Ok(sender_pubkey), Ok(recipient_pubkey)) => {
            let sol_transfer_instruction = system_instruction::transfer(
                &sender_pubkey,
                &recipient_pubkey,
                sol_transfer_request.lamports,
            );

            let transfer_instruction_accounts: Vec<String> = sol_transfer_instruction
                .accounts
                .iter()
                .map(|account_meta| account_meta.pubkey.to_string())
                .collect();

            let sol_transfer_response_data = SolTransferResponse {
                program_id: sol_transfer_instruction.program_id.to_string(),
                accounts: transfer_instruction_accounts,
                instruction_data: BASE64.encode(&sol_transfer_instruction.data),
            };

            let successful_transfer_response = ApiResponse::success(sol_transfer_response_data);
            Ok(HttpResponse::Ok().json(successful_transfer_response))
        }
        _ => {
            let invalid_address_response =
                ApiResponse::<()>::error("Invalid public key format".to_string());
            Ok(HttpResponse::BadRequest().json(invalid_address_response))
        }
    }
}

async fn send_token(token_transfer_request: web::Json<SendTokenRequest>) -> Result<HttpResponse> {
    println!("POST /send/token body: {:?}", token_transfer_request);

    // Validate amount first
    verify_token_transfer_amount(token_transfer_request.amount)?;

    // Validate all required fields
    if token_transfer_request.destination.trim().is_empty()
        || token_transfer_request.mint.trim().is_empty()
        || token_transfer_request.owner.trim().is_empty()
    {
        return Err(SolanaTransactionError("Missing required fields".to_string()).into());
    }

    // Parse and validate all public keys first
    let recipient_owner_pubkey = validate_solana_public_key(&token_transfer_request.destination)?;
    let token_mint_address = validate_solana_public_key(&token_transfer_request.mint)?;
    let current_token_owner = validate_solana_public_key(&token_transfer_request.owner)?;

    // Derive ATAs for both source and destination
    let source_associated_token_account =
        spl_associated_token_account::get_associated_token_address(
            &current_token_owner,
            &token_mint_address,
        );
    let destination_associated_token_account =
        spl_associated_token_account::get_associated_token_address(
            &recipient_owner_pubkey,
            &token_mint_address,
        );

    // Create the instruction
    let token_transfer_instruction = transfer(
        &spl_token::id(),
        &source_associated_token_account,
        &destination_associated_token_account,
        &current_token_owner,
        &[],
        token_transfer_request.amount,
    )
    .map_err(|transfer_error| {
        SolanaTransactionError(format!(
            "Failed to create transfer instruction: {}",
            transfer_error
        ))
    })?;

    let transfer_instruction_accounts: Vec<TokenAccountInfo> = token_transfer_instruction
        .accounts
        .iter()
        .map(|account_meta| TokenAccountInfo {
            pubkey: account_meta.pubkey.to_string(),
            is_signer: account_meta.is_signer,
        })
        .collect();

    let token_transfer_response_data = TokenInstructionResponse {
        program_id: token_transfer_instruction.program_id.to_string(),
        accounts: transfer_instruction_accounts,
        instruction_data: BASE64.encode(&token_transfer_instruction.data),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(token_transfer_response_data)))
}

// Add health check endpoint handler
async fn health_check() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(ApiResponse::success("Server is running")))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // Get port from environment variable or use default
    let server_port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let server_host = "0.0.0.0";
    let server_bind_address = format!("{}:{}", server_host, server_port);

    println!(
        "Starting Solana Fellowship HTTP Server on {}",
        server_bind_address
    );
    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .wrap(BlockchainRequestMonitor)
            .app_data(
                web::JsonConfig::default().error_handler(|json_error, _http_request| {
                    actix_web::error::InternalError::from_response(
                        json_error,
                        HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                            "Invalid JSON format or missing required fields".to_string(),
                        )),
                    )
                    .into()
                }),
            )
            // Add health check endpoint
            .route("/health", web::get().to(health_check))
            .route("/", web::get().to(health_check))
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
    })
    .bind(&server_bind_address)?
    .run()
    .await
}
