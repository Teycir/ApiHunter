use crate::error::CapturedError;

pub fn collect_result<T>(
    result: Result<T, CapturedError>,
    errors: &mut Vec<CapturedError>,
) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(err) => {
            errors.push(err);
            None
        }
    }
}

pub fn collect_results<T>(
    results: Vec<Result<T, CapturedError>>,
    errors: &mut Vec<CapturedError>,
) -> Vec<T> {
    results
        .into_iter()
        .filter_map(|result| collect_result(result, errors))
        .collect()
}
