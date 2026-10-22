use std::fmt::Display;

#[path = "input_common.rs"]
mod input_common;

pub const CANARY: &str = "CONFIG_SECRET_CANARY_7b2e91";

pub fn checked<T, E: Display>(result: Result<T, E>) -> Result<T, E> {
    if let Err(error) = &result {
        input_common::assert_public_error_is_clean(Err::<(), _>(error));
        assert!(
            !error.to_string().contains(CANARY),
            "configuration error exposed canary"
        );
    }
    result
}

pub fn rejected<T, E: Display>(result: Result<T, E>) -> String {
    match checked(result) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("invalid configuration was accepted"),
    }
}
