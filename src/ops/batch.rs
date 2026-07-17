use crate::error::DynError;
use serde_json::Value;
use std::collections::HashSet;

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

pub fn validate_unique_refs<'a>(
    refs: impl IntoIterator<Item = &'a str>,
    label: &str,
) -> Result<(), DynError> {
    let mut seen = HashSet::new();
    for (index, value) in refs.into_iter().enumerate() {
        if !seen.insert(value) {
            return Err(crate::error::with_prefix(
                &format!("batch item {index} failed"),
                crate::error::invalid_input(format!("{label} batch ref must be unique")),
            ));
        }
    }

    Ok(())
}

fn oversized_error(max: usize, label: &str) -> DynError {
    crate::error::invalid_input(format!(
        "{label} batch items exceeds maximum allowed value: {max}"
    ))
}
