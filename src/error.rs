use std::error::Error;

pub type DynError = Box<dyn Error + Send + Sync>;
