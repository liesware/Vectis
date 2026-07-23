// Shared helpers for fuzz targets that exercise request parsing and validation.

pub fn assert_public_error_is_clean<T, E: std::fmt::Display>(result: Result<T, E>) {
    if let Err(err) = result {
        let text = err.to_string();
        assert!(!text.chars().any(char::is_control));
    }
}
