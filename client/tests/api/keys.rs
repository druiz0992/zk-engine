use super::helpers::keys::{UserKeysRequestBody, UserKeysResponseBody};
use crate::helpers::spawn_app;
use bip39::Language;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use random_word::Lang;
use serde_json::json;

const MNEMONIC_COUNT: usize = 24;

#[tokio::test]
async fn keys_endpoint_returns_valid_user_keys_with_corrent_count() {
    let app = spawn_app().await;
    let mnemonic_request = UserKeysRequestBody::new(MNEMONIC_COUNT, Language::English);
    let body = json!(mnemonic_request);

    let response = app.post_keys_request(body).await;

    assert!(response.status().is_success());

    let user_keys: UserKeysResponseBody = response
        .json()
        .await
        .expect("Failed to deserialize response");

    assert!(!user_keys.root_key.is_empty());
    assert!(!user_keys.private_key.is_empty());
    assert!(!user_keys.nullifier_key.is_empty());
    assert!(!user_keys.public_key.is_empty());
}

#[tokio::test]
async fn keys_endpoint_returns_415_error_with_empty_request() {
    let app = spawn_app().await;
    let client = reqwest::Client::new();

    let response = client
        .post(&format!("{}/keys", app.address))
        .send()
        .await
        .expect("Failed execute request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "Expected a 415  Internal Server Error, but got {}",
        response.status()
    );
}

#[tokio::test]
async fn keys_endpoint_returns_500_error_with_invalid_count() {
    let app = spawn_app().await;
    let mnemonics = generate_mnemonic_count(20, MNEMONIC_COUNT);

    for m in mnemonics {
        let body = json!(m);
        let response = app.post_keys_request(body).await;

        assert_eq!(
            response.status(),
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            "Expected a 500  Internal Server Error, but got {}",
            response.status()
        );
    }
}

#[tokio::test]
async fn keys_endpoint_returns_500_error_with_invalid_mnemonics() {
    let app = spawn_app().await;
    let false_mnemonic = generate_invalid_mnemonic(MNEMONIC_COUNT);
    let body = json!(false_mnemonic);

    let response = app.post_keys_request(body).await;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "Expected a 500  Internal Server Error, but got {}",
        response.status()
    );
}

#[tokio::test]
async fn keys_endpoint_returns_500_error_with_non_english_mnemonics() {
    let app = spawn_app().await;
    let mnemonic_request = UserKeysRequestBody::new(MNEMONIC_COUNT, Language::French);
    let body = json!(mnemonic_request);

    let response = app.post_keys_request(body).await;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "Expected a 500  Internal Server Error, but got {}",
        response.status()
    );
}

#[tokio::test]
async fn keys_endpoint_returns_500_error_with_repeated_mnemonics() {
    let app = spawn_app().await;
    let mut mnemonic_request = UserKeysRequestBody::new(MNEMONIC_COUNT, Language::English);

    mnemonic_request.mnemonic = replace_last_word_with_first(&mnemonic_request.mnemonic).unwrap();
    let body = json!(mnemonic_request);

    let response = app.post_keys_request(body).await;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "Expected a 500  Internal Server Error, but got {}",
        response.status()
    );
}

fn generate_mnemonic_count(n: usize, exclude_count: usize) -> Vec<UserKeysRequestBody> {
    let mut rng = ChaChaRng::from_entropy();
    let mut mnemonics: Vec<UserKeysRequestBody> = Vec::new();
    let allowed_counts: [usize; 5] = [12, 15, 18, 21, 24];

    let mut has_below = false;
    let mut has_above = false;

    while mnemonics.len() < n {
        let count_idx = rng.gen_range(0..allowed_counts.len());
        let count = allowed_counts[count_idx];

        if count == exclude_count {
            continue;
        } else if count < exclude_count {
            has_below = true;
        } else {
            has_above = true;
        }

        mnemonics.push(UserKeysRequestBody::new(count, Language::English));

        // If we meet the requirement for both below and above 24, stop early if enough numbers
        if has_below && has_above && mnemonics.len() >= n {
            break;
        }
    }
    mnemonics
}

fn replace_last_word_with_first(mnemonic: &str) -> Option<String> {
    let mut words: Vec<&str> = mnemonic.split_whitespace().collect();
    if words.is_empty() {
        return None;
    }
    let first_word = words[0];
    let n = words.len();
    words[n - 1] = first_word;

    Some(words.join(" "))
}

fn generate_invalid_mnemonic(count: usize) -> UserKeysRequestBody {
    let mut mnemonic_vector = Vec::new();

    for _ in 0..count {
        mnemonic_vector.push(random_word::gen(Lang::En));
    }

    let mnemonic_str = mnemonic_vector.join(" ");
    UserKeysRequestBody {
        mnemonic: mnemonic_str.to_string(),
    }
}
