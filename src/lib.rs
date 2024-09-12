use base64;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{header, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use sha2::Sha256;
use std::collections::HashMap;
use std::str::FromStr as _;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use strum::EnumString;

mod custom_header {
    pub const CONTENT_MD5: &str = "Content-MD5";
    pub const X_CA_KEY: &str = "X-Ca-Key";
    pub const X_CA_SIGNATURE: &str = "X-Ca-Signature";
    pub const X_CA_SIGNATURE_HEADERS: &str = "X-Ca-Signature-Headers";
    pub const X_CA_TIMESTAMP: &str = "X-Ca-Timestamp";
    pub const X_CA_NONCE: &str = "X-Ca-Nonce";
}

#[derive(thiserror::Error, Debug, EnumString)]
pub enum HikError {
    #[error("System internal exception")]
    #[strum(serialize = "0x02400001")]
    SystemInternalException,
    #[error("Exception calling provider service interface")]
    #[strum(serialize = "0x02400004")]
    ProviderServiceException,
    #[error("APPKey is empty")]
    #[strum(serialize = "0x02401000")]
    EmptyAppKey,
    #[error("Partner corresponding to APPKey does not exist")]
    #[strum(serialize = "0x02401001")]
    InvalidAppKey,
    #[error("Signature is empty")]
    #[strum(serialize = "0x02401002")]
    EmptySignature,
    #[error("Signature is incorrect")]
    #[strum(serialize = "0x02401003")]
    IncorrectSignature,
    #[error("API token authentication failed")]
    #[strum(serialize = "0x02401004")]
    TokenAuthenticationFailed,
    #[error("API token is empty")]
    #[strum(serialize = "0x02401005")]
    EmptyToken,
    #[error("API token exception")]
    #[strum(serialize = "0x02401006")]
    TokenException,
    #[error("API token expired")]
    #[strum(serialize = "0x02401007")]
    TokenExpired,
    #[error("API interface unauthorized")]
    #[strum(serialize = "0x02401008")]
    UnauthorizedInterface,
    #[error("Permission verification exception")]
    #[strum(serialize = "0x02401009")]
    PermissionVerificationException,
    #[error("Parameter conversion exception")]
    #[strum(serialize = "0x0240100a")]
    ParameterConversionException,
    #[error("API interface call limit reached")]
    #[strum(serialize = "0x0240100b")]
    ApiCallLimitReached,
    #[error("Interface call statistics exception")]
    #[strum(serialize = "0x0240100c")]
    CallStatisticsException,
    #[error("Partner IP restricted")]
    #[strum(serialize = "0x0240101b")]
    IpRestricted,
    #[error("Partner MAC restricted")]
    #[strum(serialize = "0x0240101c")]
    MacRestricted,
    #[error("Partner IP and MAC restricted")]
    #[strum(serialize = "0x0240101d")]
    IpMacRestricted,
    #[error("Exception parsing request JSON data")]
    #[strum(serialize = "0x02401021")]
    RequestJsonParseException,
    #[error("Exception parsing response JSON data")]
    #[strum(serialize = "0x02401022")]
    ResponseJsonParseException,
    #[error("Unsupported request encoding character set")]
    #[strum(serialize = "0x02401023")]
    UnsupportedCharset,
    #[error("Backend service unavailable, reason unknown")]
    #[strum(serialize = "0x02401030")]
    BackendServiceUnavailable,
    #[error("Backend service connection timeout")]
    #[strum(serialize = "0x02401031")]
    BackendConnectionTimeout,
    #[error("Backend service connection refused")]
    #[strum(serialize = "0x02401032")]
    BackendConnectionRefused,
    #[error("Backend service read data timeout")]
    #[strum(serialize = "0x02401033")]
    BackendReadTimeout,
    #[error("Backend service circuit breaker")]
    #[strum(serialize = "0x02401034")]
    BackendCircuitBreaker,
    #[error("Hystrix timeout")]
    #[strum(serialize = "0x02401035")]
    HystrixTimeout,
    #[error("Access frequency exceeds system limit")]
    #[strum(serialize = "0x02401036")]
    AccessFrequencyExceeded,
    #[error("Backend service no response")]
    #[strum(serialize = "0x02401037")]
    BackendNoResponse,
    #[error("No available service address")]
    #[strum(serialize = "0x02401038")]
    NoAvailableServiceAddress,
    #[error("API gateway zuul plugin exception")]
    #[strum(serialize = "0x02401039")]
    ZuulPluginException,
    #[error("Component not installed")]
    #[strum(serialize = "0x0240103a")]
    ComponentNotInstalled,
    #[error("Interface call frequency exceeds interface limit")]
    #[strum(serialize = "0x0240103b")]
    InterfaceFrequencyExceeded,
    #[error("Interface does not support http calls")]
    #[strum(serialize = "0x0240103c")]
    HttpNotSupported,
    #[error("Required parameter is empty")]
    #[strum(serialize = "0x00072001")]
    EmptyRequiredParameter,
    #[error("Parameter range incorrect")]
    #[strum(serialize = "0x00072002")]
    IncorrectParameterRange,
    #[error("Parameter format incorrect")]
    #[strum(serialize = "0x00072003")]
    IncorrectParameterFormat,
    #[error("Response message too long")]
    #[strum(serialize = "0x00072004")]
    ResponseTooLong,
    #[error("Parameter does not exist")]
    #[strum(serialize = "0x00072005")]
    NonexistentParameter,
    #[error("Parameter content too long")]
    #[strum(serialize = "0x00072006")]
    ParameterContentTooLong,
    #[error("Service performance at limit")]
    #[strum(serialize = "0x00052101")]
    ServicePerformanceLimit,
    #[error("Service error")]
    #[strum(serialize = "0x00052102")]
    ServiceError,
    #[error("Service response timeout")]
    #[strum(serialize = "0x00052103")]
    ServiceResponseTimeout,
    #[error("Service unavailable")]
    #[strum(serialize = "0x00052104")]
    ServiceUnavailable,
    #[error("Resource access unauthorized")]
    #[strum(serialize = "0x00072201")]
    UnauthorizedResourceAccess,
    #[error("Resource does not exist")]
    #[strum(serialize = "0x00072202")]
    NonexistentResource,
    #[error("License quantity limited")]
    #[strum(serialize = "0x00072203")]
    LicenseQuantityLimited,
    #[error("License does not provide this feature")]
    #[strum(serialize = "0x00072204")]
    LicenseFeatureUnavailable,
    #[error("Other unknown error")]
    #[strum(serialize = "0x00052301")]
    UnknownError,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("HTTP request error: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("JSON serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("URL parsing error: {0}")]
    UrlParseError(#[from] url::ParseError),

    #[error("Hikvision API error: {0}")]
    HikError(#[from] HikError),

    #[error("Invalid response format")]
    InvalidResponseFormat,

    #[error("Unexpected server response: {0}")]
    UnexpectedResponse(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct Client {
    client: reqwest::Client,
    base_url: Url,
    app_key: String,
    secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Response<T> {
    pub code: String,
    pub msg: String,
    pub data: ResponseData<T>,
}

impl<T> Response<T> {
    /// Consume the error and return the data
    pub fn consume_error(self) -> Result<T> {
        if self.code != "0" {
            Err(Error::HikError(HikError::from_str(&self.code).unwrap()))
        } else {
            match self.data {
                ResponseData::Data(data) => Ok(data),
                ResponseData::Empty(_) => unreachable!(),
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum ResponseData<T> {
    Data(T),
    Empty(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Data {
    pub total: i32,
    pub page_size: i32,
    pub page_no: i32,
    pub list: Vec<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Protocol {
    Rtsp,
    Rtmp,
    Hls,
}

#[derive(Debug, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum StreamType {
    MainStream = 0,
    SubStream = 1,
    ThirdStream = 2,
}

#[derive(Debug, Serialize_repr, Deserialize_repr, Default)]
#[repr(u8)]
pub enum TransportMode {
    Udp = 0,
    #[default]
    Tcp = 1,
}

#[derive(Debug, Serialize)]
pub struct PreviewCameraRequest {
    pub camera_index_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_type: Option<StreamType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transmode: Option<TransportMode>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreviewCameraResponse {
    pub url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListCameraRequest {
    pub page_no: String,
    pub page_size: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListCameraResponse {
    pub total: u32,
    pub page_no: u32,
    pub page_size: u32,
}

impl Client {
    pub fn new(base_url: Url, app_key: String, secret: String) -> Self {
        Self {
            client: reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap(),
            base_url,
            app_key: app_key,
            secret: secret,
        }
    }

    pub async fn preview_camera(
        &self,
        request: PreviewCameraRequest,
    ) -> Result<PreviewCameraResponse> {
        Ok(self
            .post("/api/video/v2/cameras/previewURLs", request)
            .await?)
    }

    pub async fn list_cameras(&self, request: ListCameraRequest) -> Result<ListCameraResponse> {
        Ok(self
            .post("/artemis/api/resource/v1/cameras", request)
            .await?)
    }

    pub async fn post<T, R>(&self, endpoint: &str, body: T) -> Result<R>
    where
        T: Serialize,
        R: DeserializeOwned,
    {
        let full_url = self.base_url.join(endpoint).unwrap();
        let mut headers = HeaderMap::new();
        let body_json = serde_json::to_string(&body).unwrap();
        self.init_request(&mut headers, endpoint, &body_json, reqwest::Method::POST)?;

        let response = self
            .client
            .post(full_url)
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/json")
            .headers(headers)
            .body(body_json)
            .send()
            .await?
            .json::<Response<R>>()
            .await?;

        Ok(response.consume_error()?)
    }

    fn init_request(
        &self,
        headers: &mut HeaderMap,
        url: &str,
        body: &str,
        method: reqwest::Method,
    ) -> reqwest::Result<()> {
        headers.insert(reqwest::header::ACCEPT, "application/json".parse().unwrap());
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        // if method == reqwest::Method::POST {
        //     headers.insert(
        //         custom_header::CONTENT_MD5,
        //         compute_content_md5(body).parse().unwrap(),
        //     );
        // }

        headers.insert(
            custom_header::X_CA_TIMESTAMP,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
                .to_string()
                .try_into()
                .unwrap(),
        );

        headers.insert(
            custom_header::X_CA_NONCE,
            Uuid::new_v4().to_string().try_into().unwrap(),
        );
        headers.insert(
            custom_header::X_CA_KEY,
            self.app_key.clone().try_into().unwrap(),
        );

        let str_to_sign = build_sign_string(headers, url, method);
        let signed_str = compute_for_hmac_sha256(&str_to_sign, &self.secret);
        headers.insert(
            custom_header::X_CA_SIGNATURE,
            signed_str.try_into().unwrap(),
        );

        Ok(())
    }
}

fn compute_content_md5(body: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(body);
    let result = hasher.finalize();
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD.encode(format!("{:x?}", result))
}

fn compute_for_hmac_sha256(str: &str, secret: &str) -> String {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac: HmacSha256 = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(str.as_bytes());
    let result = mac.finalize();
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD.encode(result.into_bytes())
}

/// url - endpoint wth query
fn build_sign_string(headers: &mut HeaderMap, url: &str, method: reqwest::Method) -> String {
    let mut sign = Vec::new();
    sign.push(format!("{} \n", method.to_string().to_uppercase()));

    if let Some(accept) = headers.get(reqwest::header::ACCEPT) {
        sign.push(format!("{} \n", accept.to_str().unwrap()));
    }
    if let Some(content_md5) = headers.get(custom_header::CONTENT_MD5) {
        sign.push(format!("{} \n", content_md5.to_str().unwrap()));
    }
    if let Some(content_type) = headers.get(reqwest::header::CONTENT_TYPE) {
        sign.push(format!("{} \n", content_type.to_str().unwrap()));
    }
    if let Some(date) = headers.get(reqwest::header::DATE) {
        sign.push(format!("{} \n", date.to_str().unwrap()));
    }

    sign.push(build_sign_header(headers));
    sign.push(url.to_string());

    sign.join("")
}

/// add X-Ca-Signature-Headers to headers
/// return multiline string to be signed
fn build_sign_header(header: &mut HeaderMap) -> String {
    let mut sorted_kv = header
        .iter()
        .map(|(k, v)| (k.to_string().to_lowercase(), v.to_str().unwrap().to_owned()))
        .filter(|(k, _)| k.starts_with("x-ca-"))
        .collect::<Vec<_>>();
    sorted_kv.sort_by(|a, b| a.0.cmp(&b.0));

    header.insert(
        custom_header::X_CA_SIGNATURE_HEADERS,
        sorted_kv
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<&str>>()
            .join(",")
            .try_into()
            .unwrap(),
    );

    sorted_kv
        .iter()
        .map(|(k, v)| format!("{}:{}", k, v))
        .collect::<Vec<String>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_build_sign_string() {
        let url = "/artemis/api/resource/v1/cameras";
        let method = reqwest::Method::POST;
        let key = "28057000";
        let secret = "dZztQSS0000kLpURG000";

        let client = Client::new(
            Url::parse("http://127.0.0.1:9999").unwrap(),
            key.to_string(),
            secret.to_string(),
        );

        let request = ListCameraRequest {
            page_no: "1".to_string(),
            page_size: "10".to_string(),
        };

        let response = client.list_cameras(request).await.unwrap();
        println!("{:?}", response);
    }
}
