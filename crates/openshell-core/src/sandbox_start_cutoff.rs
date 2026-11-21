// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::time::{SystemTime, UNIX_EPOCH};

use tonic::{Request, Status};

pub const HEADER: &str = "openshell-start-before-unix-ms";

/// An optional limit on starting a mutation, independent of its runtime.
#[derive(Clone, Copy, Debug, Default)]
pub struct StartCutoff(Option<u64>);

impl StartCutoff {
    pub fn from_required_header<T>(request: &Request<T>) -> Result<Self, Status> {
        let mut values = request.metadata().get_all(HEADER).iter();
        let Some(value) = values.next() else {
            return Err(Status::invalid_argument(
                "a sandbox start cutoff is required",
            ));
        };
        if values.next().is_some() {
            return Err(Status::invalid_argument("send one sandbox start cutoff"));
        }
        let cutoff = value
            .to_str()
            .ok()
            .filter(|value| value.len() <= 20 && value.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                Status::invalid_argument("sandbox start cutoff must be Unix milliseconds")
            })?;
        let limit = Self(Some(cutoff));
        limit.check()?;
        Ok(limit)
    }

    pub fn is_set(self) -> bool {
        self.0.is_some()
    }

    pub fn check(self) -> Result<(), Status> {
        if let Some(cutoff) = self.0 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Status::unavailable("the gateway clock is unavailable"))?;
            if now.as_millis() >= u128::from(cutoff) {
                return Err(Status::deadline_exceeded("sandbox start cutoff expired"));
            }
        }
        Ok(())
    }

    pub fn insert<T>(self, mut request: Request<T>) -> Request<T> {
        if self.is_set() {
            request.extensions_mut().insert(self);
        }
        request
    }

    pub fn get<T>(request: &Request<T>) -> Self {
        request
            .extensions()
            .get::<Self>()
            .copied()
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_single_future_cutoff_admits_a_new_mutation() {
        let mut request = Request::new(());
        assert_eq!(
            StartCutoff::from_required_header(&request)
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        request.metadata_mut().insert(HEADER, "1".parse().unwrap());
        assert_eq!(
            StartCutoff::from_required_header(&request)
                .unwrap_err()
                .code(),
            tonic::Code::DeadlineExceeded
        );
        request
            .metadata_mut()
            .insert(HEADER, "+500".parse().unwrap());
        assert_eq!(
            StartCutoff::from_required_header(&request)
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        request.metadata_mut().append(HEADER, "1".parse().unwrap());
        assert_eq!(
            StartCutoff::from_required_header(&request)
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }
}
