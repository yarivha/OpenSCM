// Tests for static-asset cache validators.
//
// Every page pulls ~4.8 MB of vendor JS/CSS. These assertions pin the
// behaviour that keeps repeat navigations from re-downloading all of it:
// a strong ETag on every hit, and a 304 (empty body) when the browser
// revalidates with that ETag.

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use std::path::PathBuf;

// A real asset that exists in the embedded bundle.
const ASSET: &str = "plugins/jquery/jquery.min.js";

#[tokio::test]
async fn first_request_carries_etag_and_cache_control() {
    let resp = scmserver::serve_embedded_static_file(PathBuf::from(ASSET), HeaderMap::new())
        .await
        .into_response();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get(header::ETAG).is_some(), "asset must carry a validator");
    let cc = resp.headers().get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok()).unwrap_or("");
    assert!(cc.contains("max-age"), "asset must be cacheable, got {cc:?}");
}

#[tokio::test]
async fn revalidation_with_matching_etag_returns_304_without_a_body() {
    // First fetch to learn the ETag.
    let first = scmserver::serve_embedded_static_file(PathBuf::from(ASSET), HeaderMap::new())
        .await
        .into_response();
    let etag = first.headers().get(header::ETAG).unwrap().clone();

    // Browser revalidates with it.
    let mut headers = HeaderMap::new();
    headers.insert(header::IF_NONE_MATCH, etag.clone());
    let second = scmserver::serve_embedded_static_file(PathBuf::from(ASSET), headers)
        .await
        .into_response();

    assert_eq!(second.status(), StatusCode::NOT_MODIFIED, "unchanged asset must 304");
    assert_eq!(second.headers().get(header::ETAG), Some(&etag), "304 repeats the validator");
}

#[tokio::test]
async fn a_stale_etag_still_serves_the_file() {
    // After an upgrade the client's old validator no longer matches, so the
    // new bytes must be sent rather than a 304 pinning stale assets.
    let mut headers = HeaderMap::new();
    headers.insert(header::IF_NONE_MATCH, "\"0.0.0-deadbeef\"".parse().unwrap());
    let resp = scmserver::serve_embedded_static_file(PathBuf::from(ASSET), headers)
        .await
        .into_response();

    assert_eq!(resp.status(), StatusCode::OK, "a non-matching validator must re-send the asset");
}

#[tokio::test]
async fn distinct_assets_get_distinct_etags() {
    let a = scmserver::serve_embedded_static_file(PathBuf::from(ASSET), HeaderMap::new())
        .await.into_response();
    let b = scmserver::serve_embedded_static_file(
        PathBuf::from("plugins/chart.js/Chart.min.js"), HeaderMap::new())
        .await.into_response();

    assert_ne!(
        a.headers().get(header::ETAG), b.headers().get(header::ETAG),
        "different assets must not share a validator, or one would mask the other"
    );
}
