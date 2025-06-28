# confirm_email

A lightweight Rust crate for secure email confirmation workflows in web applications and services.

## Purpose

The `confirm_email` crate addresses a common requirement in user registration systems: verifying that users have access to the email addresses they provide. When users register for an account, the system needs to confirm their email address before fully activating their account or granting access to certain features.

This library generates secure, encrypted tokens that can be embedded in confirmation emails sent to users. When users click the confirmation link, the application validates the token to verify the email address and complete the registration process. The tokens contain the user's email address and an expiration timestamp, ensuring that confirmation links remain valid only for a specified period.

The crate is designed for applications that need reliable email verification without the complexity of managing token storage in databases or external services. All token information is self-contained and cryptographically protected, making the system both secure and stateless.

## Key Features

The library provides encrypted, URL-safe tokens that can be safely transmitted in email links. Token validity periods are configurable, with a sensible default of one day for most use cases. The validation process returns clear success or failure results, allowing applications to provide appropriate feedback to users during the confirmation process.

## Installation

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
confirm_email = "0.1"
```

## Usage

### Basic Email Confirmation Flow

```rust
use confirm_email::{generate_token, validate};

// Generate a confirmation token when a user registers
let confirmation_token = generate_token(
    "user@example.com".to_string(),
    "your_secret_key".to_string(),
).expect("Failed to generate confirmation token");

// Send the token in an email confirmation link
// https://yourapp.com/confirm?token={confirmation_token}

// Later, when the user clicks the confirmation link, validate the token
match validate(confirmation_token, "your_secret_key".to_string()) {
    Ok(email) => {
        // Email confirmed successfully - activate the user account
        println!("Confirmed email address: {}", email);
    },
    Err(_) => {
        // Token is invalid or expired - show error message
        println!("Invalid or expired confirmation link");
    },
}
```

### Custom Expiration Times

```rust
use confirm_email::generate_token_with_expiration;

// Generate a token that expires in 2 hours for time-sensitive confirmations
let short_lived_token = generate_token_with_expiration(
    "user@example.com".to_string(),
    "your_secret_key".to_string(),
    7200, // 2 hours in seconds
).expect("Failed to generate token");
```

### Integration Example

```rust
use confirm_email::{generate_token, validate, error::Error};

fn send_confirmation_email(user_email: &str, secret_key: &str) -> Result<(), String> {
    let token = generate_token(user_email.to_string(), secret_key.to_string())
        .map_err(|_| "Failed to generate confirmation token")?;
    
    let confirmation_url = format!("https://yourapp.com/confirm?token={}", token);
    
    // Send email with confirmation_url
    // Your email sending logic here
    
    Ok(())
}

fn handle_confirmation(token: &str, secret_key: &str) -> Result<String, String> {
    match validate(token.to_string(), secret_key.to_string()) {
        Ok(email) => {
            // Update user status in database
            // Mark email as confirmed
            Ok(email)
        },
        Err(Error::Expired(_)) => Err("Confirmation link has expired".to_string()),
        Err(_) => Err("Invalid confirmation link".to_string()),
    }
}
```
