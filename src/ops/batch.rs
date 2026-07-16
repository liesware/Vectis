use crate::error::DynError;
use serde_json::Value;

pub fn reject_oversized_value(request: &Value, max: usize, label: &str) -> Result<(), DynError> {
    if let Some(items) = request.get("items").and_then(Value::as_array)
        && items.len() > max
    {
        return Err(oversized_error(max, label));
    }

    Ok(())
}

pub fn validate_len(len: usize, max: usize, label: &str) -> Result<(), DynError> {
    if len == 0 {
        return Err(crate::error::invalid_input(format!(
            "{label} batch items must not be empty"
        )));
    }
    if len > max {
        return Err(oversized_error(max, label));
    }

    Ok(())
}

fn oversized_error(max: usize, label: &str) -> DynError {
    crate::error::invalid_input(format!(
        "{label} batch items exceeds maximum allowed value: {max}"
    ))
}
