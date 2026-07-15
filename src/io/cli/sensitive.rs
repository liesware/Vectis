use std::io::{self, IsTerminal};

pub const SENSITIVE_STDOUT_WARNING: &str =
    "Warning: sensitive material will be printed to the terminal. Store it securely.";

pub fn warn_if_stdout_is_terminal() {
    if let Some(warning) = sensitive_stdout_warning(io::stdout().is_terminal()) {
        eprintln!("{warning}");
    }
}

pub(crate) fn sensitive_stdout_warning(stdout_is_terminal: bool) -> Option<&'static str> {
    stdout_is_terminal.then_some(SENSITIVE_STDOUT_WARNING)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warning_is_emitted_only_for_terminal_stdout() {
        assert_eq!(
            sensitive_stdout_warning(true),
            Some(SENSITIVE_STDOUT_WARNING)
        );
        assert_eq!(sensitive_stdout_warning(false), None);
    }
}
