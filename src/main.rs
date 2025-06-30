use actix_web::{App, HttpResponse, HttpServer, Result, middleware::Logger, web};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
};
use solana_system_interface::instruction as system_instruction;
use spl_token::instruction::{initialize_mint, mint_to, transfer};
use std::str::FromStr;

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
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

// Request/Response structures
#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
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

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
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
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

// Helper functions
fn parse_pubkey(key_str: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(key_str).map_err(|e| format!("Invalid public key: {}", e))
}

fn parse_keypair(secret_str: &str) -> Result<Keypair, String> {
    let bytes = bs58::decode(secret_str)
        .into_vec()
        .map_err(|e| format!("Invalid base58 secret key: {}", e))?;

    if bytes.len() != 64 {
        return Err("Invalid secret key length".to_string());
    }

    Keypair::try_from(&bytes[..]).map_err(|e| format!("Invalid keypair: {}", e))
}

// Endpoint handlers
async fn generate_keypair() -> Result<HttpResponse> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    let response = ApiResponse::success(KeypairResponse { pubkey, secret });
    Ok(HttpResponse::Ok().json(response))
}

async fn create_token(req: web::Json<CreateTokenRequest>) -> Result<HttpResponse> {
    match (parse_pubkey(&req.mint_authority), parse_pubkey(&req.mint)) {
        (Ok(mint_authority), Ok(mint)) => {
            let instruction = initialize_mint(
                &spl_token::id(),
                &mint,
                &mint_authority,
                Some(&mint_authority),
                req.decimals,
            )
            .map_err(|e| format!("Failed to create mint instruction: {}", e));

            match instruction {
                Ok(ix) => {
                    let accounts: Vec<AccountInfo> = ix
                        .accounts
                        .iter()
                        .map(|acc| AccountInfo {
                            pubkey: acc.pubkey.to_string(),
                            is_signer: acc.is_signer,
                            is_writable: acc.is_writable,
                        })
                        .collect();

                    let response_data = InstructionResponse {
                        program_id: ix.program_id.to_string(),
                        accounts,
                        instruction_data: BASE64.encode(&ix.data),
                    };

                    let response = ApiResponse::success(response_data);
                    Ok(HttpResponse::Ok().json(response))
                }
                Err(e) => {
                    let response = ApiResponse::<()>::error(e);
                    Ok(HttpResponse::BadRequest().json(response))
                }
            }
        }
        _ => {
            let response = ApiResponse::<()>::error("Invalid public key format".to_string());
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

async fn mint_token(req: web::Json<MintTokenRequest>) -> Result<HttpResponse> {
    match (
        parse_pubkey(&req.mint),
        parse_pubkey(&req.destination),
        parse_pubkey(&req.authority),
    ) {
        (Ok(mint), Ok(destination), Ok(authority)) => {
            let instruction = mint_to(
                &spl_token::id(),
                &mint,
                &destination,
                &authority,
                &[],
                req.amount,
            )
            .map_err(|e| format!("Failed to create mint instruction: {}", e));

            match instruction {
                Ok(ix) => {
                    let accounts: Vec<AccountInfo> = ix
                        .accounts
                        .iter()
                        .map(|acc| AccountInfo {
                            pubkey: acc.pubkey.to_string(),
                            is_signer: acc.is_signer,
                            is_writable: acc.is_writable,
                        })
                        .collect();

                    let response_data = InstructionResponse {
                        program_id: ix.program_id.to_string(),
                        accounts,
                        instruction_data: BASE64.encode(&ix.data),
                    };

                    let response = ApiResponse::success(response_data);
                    Ok(HttpResponse::Ok().json(response))
                }
                Err(e) => {
                    let response = ApiResponse::<()>::error(e);
                    Ok(HttpResponse::BadRequest().json(response))
                }
            }
        }
        _ => {
            let response = ApiResponse::<()>::error("Invalid public key format".to_string());
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

async fn sign_message(req: web::Json<SignMessageRequest>) -> Result<HttpResponse> {
    if req.message.is_empty() || req.secret.is_empty() {
        let response = ApiResponse::<()>::error("Missing required fields".to_string());
        return Ok(HttpResponse::BadRequest().json(response));
    }

    match parse_keypair(&req.secret) {
        Ok(keypair) => {
            let message_bytes = req.message.as_bytes();
            let signature = keypair.sign_message(message_bytes);

            let response_data = SignMessageResponse {
                signature: BASE64.encode(signature.as_ref()),
                public_key: keypair.pubkey().to_string(),
                message: req.message.clone(),
            };

            let response = ApiResponse::success(response_data);
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            let response = ApiResponse::<()>::error(e);
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

async fn verify_message(req: web::Json<VerifyMessageRequest>) -> Result<HttpResponse> {
    match parse_pubkey(&req.pubkey) {
        Ok(pubkey) => {
            let signature_bytes = match BASE64.decode(&req.signature) {
                Ok(bytes) => bytes,
                Err(_) => {
                    let response = ApiResponse::<()>::error("Invalid base64 signature".to_string());
                    return Ok(HttpResponse::BadRequest().json(response));
                }
            };

            let signature = match Signature::try_from(signature_bytes.as_slice()) {
                Ok(sig) => sig,
                Err(_) => {
                    let response = ApiResponse::<()>::error("Invalid signature format".to_string());
                    return Ok(HttpResponse::BadRequest().json(response));
                }
            };

            let message_bytes = req.message.as_bytes();
            let valid = signature.verify(&pubkey.to_bytes(), message_bytes);

            let response_data = VerifyMessageResponse {
                valid,
                message: req.message.clone(),
                pubkey: req.pubkey.clone(),
            };

            let response = ApiResponse::success(response_data);
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            let response = ApiResponse::<()>::error(e);
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

async fn send_sol(req: web::Json<SendSolRequest>) -> Result<HttpResponse> {
    if req.lamports == 0 {
        let response =
            ApiResponse::<()>::error("Invalid amount: must be greater than 0".to_string());
        return Ok(HttpResponse::BadRequest().json(response));
    }

    match (parse_pubkey(&req.from), parse_pubkey(&req.to)) {
        (Ok(from), Ok(to)) => {
            let instruction = system_instruction::transfer(&from, &to, req.lamports);

            let accounts: Vec<AccountInfo> = instruction
                .accounts
                .iter()
                .map(|acc| AccountInfo {
                    pubkey: acc.pubkey.to_string(),
                    is_signer: acc.is_signer,
                    is_writable: acc.is_writable,
                })
                .collect();

            let response_data = InstructionResponse {
                program_id: instruction.program_id.to_string(),
                accounts,
                instruction_data: BASE64.encode(&instruction.data),
            };

            let response = ApiResponse::success(response_data);
            Ok(HttpResponse::Ok().json(response))
        }
        _ => {
            let response = ApiResponse::<()>::error("Invalid public key format".to_string());
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

async fn send_token(req: web::Json<SendTokenRequest>) -> Result<HttpResponse> {
    if req.amount == 0 {
        let response =
            ApiResponse::<()>::error("Invalid amount: must be greater than 0".to_string());
        return Ok(HttpResponse::BadRequest().json(response));
    }

    match (
        parse_pubkey(&req.destination),
        parse_pubkey(&req.mint),
        parse_pubkey(&req.owner),
    ) {
        (Ok(destination), Ok(mint), Ok(owner)) => {
            // For SPL token transfer, we need to derive the associated token accounts
            let source_ata =
                spl_associated_token_account::get_associated_token_address(&owner, &mint);

            let instruction = transfer(
                &spl_token::id(),
                &source_ata,
                &destination,
                &owner,
                &[],
                req.amount,
            )
            .map_err(|e| format!("Failed to create transfer instruction: {}", e));

            match instruction {
                Ok(ix) => {
                    let accounts: Vec<AccountInfo> = ix
                        .accounts
                        .iter()
                        .map(|acc| AccountInfo {
                            pubkey: acc.pubkey.to_string(),
                            is_signer: acc.is_signer,
                            is_writable: acc.is_writable,
                        })
                        .collect();

                    let response_data = InstructionResponse {
                        program_id: ix.program_id.to_string(),
                        accounts,
                        instruction_data: BASE64.encode(&ix.data),
                    };

                    let response = ApiResponse::success(response_data);
                    Ok(HttpResponse::Ok().json(response))
                }
                Err(e) => {
                    let response = ApiResponse::<()>::error(e);
                    Ok(HttpResponse::BadRequest().json(response))
                }
            }
        }
        _ => {
            let response = ApiResponse::<()>::error("Invalid public key format".to_string());
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    println!("Starting Solana Fellowship HTTP Server on http://localhost:8080");

    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
