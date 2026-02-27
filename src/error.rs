use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum KmsError {
    #[error("Validation Error: {0}")]
    ValidationError(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not Found: {0}")]
    NotFound(String),

    #[error("Rate Limit Exceeded")]
    RateLimitExceeded,

    #[error("Service Unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Internal Server Error: {0}")]
    InternalError(String),
}

impl KmsError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::ValidationError(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::FORBIDDEN,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::ValidationError(_) => "bad_request",
            Self::Unauthorized(_) => "unauthorized",
            Self::Forbidden(_) => "forbidden",
            Self::NotFound(_) => "not_found",
            Self::RateLimitExceeded => "rate_limited",
            Self::ServiceUnavailable(_) => "service_unavailable",
            Self::InternalError(_) => "internal_error",
        }
    }

    fn message(&self) -> String {
        match self {
            Self::ValidationError(m)
            | Self::Unauthorized(m)
            | Self::Forbidden(m)
            | Self::NotFound(m)
            | Self::ServiceUnavailable(m)
            | Self::InternalError(m) => m.clone(),
            Self::RateLimitExceeded => "Rate limit exceeded".to_string(),
        }
    }
}

impl IntoResponse for KmsError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let code = self.code();
        let message = self.message();

        let body = Json(json!({
            "code": code,
            "message": message
        }));

        (status, body).into_response()
    }
}
