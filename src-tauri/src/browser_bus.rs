//! Unified browser execution bus.
//!
//! Native CDP short-lived sessions for Agent/Tauri `browser_*` commands.
//! UI may still hold its own screencast WebSocket; command traffic is serialized
//! through this bus so Agent never "owns" a parallel long-lived CDP client.

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::timeout;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

const CDP_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug)]
pub struct BrowserBus {
    debugger_url: String,
    next_id: std::sync::Arc<AtomicU64>,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserEvaluateResult {
    pub expression: String,
    pub value: Value,
    pub exception: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserScreenshotResult {
    pub format: String,
    pub base64: String,
    pub bytes: usize,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserClickResult {
    pub mode: String,
    pub x: f64,
    pub y: f64,
    pub selector: Option<String>,
}

impl BrowserBus {
    pub fn new(debugger_url: impl Into<String>) -> Self {
        Self {
            debugger_url: debugger_url.into(),
            next_id: std::sync::Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn debugger_url(&self) -> &str {
        &self.debugger_url
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        call_cdp(&self.debugger_url, &self.next_id, method, params).await
    }

    pub async fn evaluate(
        &self,
        expression: &str,
        await_promise: bool,
    ) -> Result<BrowserEvaluateResult, String> {
        let result = self
            .call(
                "Runtime.evaluate",
                json!({
                    "expression": expression,
                    "returnByValue": true,
                    "awaitPromise": await_promise,
                    "userGesture": true,
                }),
            )
            .await?;
        if let Some(exception) = result
            .pointer("/exceptionDetails/text")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                result
                    .pointer("/exceptionDetails/exception/description")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
        {
            return Ok(BrowserEvaluateResult {
                expression: expression.to_string(),
                value: Value::Null,
                exception: Some(exception),
            });
        }
        let value = result
            .pointer("/result/value")
            .cloned()
            .unwrap_or(Value::Null);
        Ok(BrowserEvaluateResult {
            expression: expression.to_string(),
            value,
            exception: None,
        })
    }

    pub async fn navigate(&self, url: &str) -> Result<Value, String> {
        self.call("Page.enable", json!({})).await.ok();
        self.call("Page.navigate", json!({ "url": url })).await
    }

    pub async fn screenshot(&self, format: &str) -> Result<BrowserScreenshotResult, String> {
        let format = match format.trim().to_ascii_lowercase().as_str() {
            "jpeg" | "jpg" => "jpeg",
            _ => "png",
        };
        self.call("Page.enable", json!({})).await.ok();
        let result = self
            .call(
                "Page.captureScreenshot",
                json!({
                    "format": format,
                    "fromSurface": true,
                }),
            )
            .await?;
        let base64 = result
            .get("data")
            .and_then(Value::as_str)
            .ok_or_else(|| "CDP screenshot missing data".to_string())?
            .to_string();
        let bytes = base64.len() * 3 / 4;
        Ok(BrowserScreenshotResult {
            format: format.to_string(),
            base64,
            bytes,
        })
    }

    pub async fn click_xy(&self, x: f64, y: f64) -> Result<BrowserClickResult, String> {
        self.call(
            "Input.dispatchMouseEvent",
            json!({
                "type": "mouseMoved",
                "x": x,
                "y": y,
                "button": "none",
                "buttons": 0,
                "pointerType": "mouse",
            }),
        )
        .await?;
        self.call(
            "Input.dispatchMouseEvent",
            json!({
                "type": "mousePressed",
                "x": x,
                "y": y,
                "button": "left",
                "buttons": 1,
                "clickCount": 1,
                "pointerType": "mouse",
            }),
        )
        .await?;
        self.call(
            "Input.dispatchMouseEvent",
            json!({
                "type": "mouseReleased",
                "x": x,
                "y": y,
                "button": "left",
                "buttons": 0,
                "clickCount": 1,
                "pointerType": "mouse",
            }),
        )
        .await?;
        Ok(BrowserClickResult {
            mode: "xy".into(),
            x,
            y,
            selector: None,
        })
    }

    pub async fn click_selector(&self, selector: &str) -> Result<BrowserClickResult, String> {
        let expression = format!(
            r#"(function(){{
  const el = document.querySelector({selector});
  if (!el) return null;
  el.scrollIntoView({{ block: "center", inline: "center" }});
  const r = el.getBoundingClientRect();
  return {{ x: r.x + r.width / 2, y: r.y + r.height / 2, w: r.width, h: r.height }};
}})()"#,
            selector = serde_json::to_string(selector).unwrap_or_else(|_| "\"\"".into())
        );
        let evaluated = self.evaluate(&expression, false).await?;
        if let Some(error) = evaluated.exception {
            return Err(error);
        }
        let x = evaluated
            .value
            .get("x")
            .and_then(Value::as_f64)
            .ok_or_else(|| format!("selector not found or not visible: {selector}"))?;
        let y = evaluated
            .value
            .get("y")
            .and_then(Value::as_f64)
            .ok_or_else(|| format!("selector missing coordinates: {selector}"))?;
        let mut result = self.click_xy(x, y).await?;
        result.mode = "selector".into();
        result.selector = Some(selector.to_string());
        Ok(result)
    }

    pub async fn insert_text(&self, text: &str) -> Result<Value, String> {
        self.call("Input.insertText", json!({ "text": text })).await
    }

    pub async fn dispatch_key(
        &self,
        key: &str,
        code: Option<&str>,
        pressed: bool,
    ) -> Result<Value, String> {
        let type_name = if pressed { "keyDown" } else { "keyUp" };
        self.call(
            "Input.dispatchKeyEvent",
            json!({
                "type": type_name,
                "key": key,
                "code": code.unwrap_or(key),
                "windowsVirtualKeyCode": 0,
                "nativeVirtualKeyCode": 0,
            }),
        )
        .await
    }
}

async fn call_cdp(
    debugger_url: &str,
    next_id: &AtomicU64,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    let id = next_id.fetch_add(1, Ordering::SeqCst);
    let request = json!({
        "id": id,
        "method": method,
        "params": params,
    });
    let (stream, _) = timeout(CDP_TIMEOUT, connect_async(debugger_url))
        .await
        .map_err(|_| "CDP 连接超时".to_string())?
        .map_err(|error| format!("CDP 连接失败: {error}"))?;
    let (mut write, mut read) = stream.split();

    let payload = serde_json::to_string(&request).map_err(|error| error.to_string())?;
    write
        .send(Message::Text(payload.into()))
        .await
        .map_err(|error| format!("CDP 发送失败: {error}"))?;

    let deadline = timeout(CDP_TIMEOUT, async {
        while let Some(message) = read.next().await {
            let message = message.map_err(|error| format!("CDP 读取失败: {error}"))?;
            let text = match message {
                Message::Text(text) => text.to_string(),
                Message::Binary(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
                Message::Close(_) => return Err("CDP 连接已关闭".to_string()),
            };
            let value: Value =
                serde_json::from_str(&text).map_err(|error| format!("CDP JSON 无效: {error}"))?;
            if value.get("id").and_then(Value::as_u64) != Some(id) {
                // Event / other response; ignore for request-response API.
                continue;
            }
            if let Some(error) = value.get("error") {
                let message = error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown CDP error");
                return Err(format!("CDP {method} 失败: {message}"));
            }
            return Ok(value.get("result").cloned().unwrap_or(Value::Null));
        }
        Err("CDP 无响应".to_string())
    })
    .await
    .map_err(|_| "CDP 等待响应超时".to_string())??;

    let _ = write.close().await;
    Ok(deadline)
}

/// Pure helper for tests and agent previews.
pub fn build_evaluate_expression_for_selector(selector: &str) -> String {
    format!(
        r#"(function(){{ const el = document.querySelector({}); if(!el) return null; const r = el.getBoundingClientRect(); return {{x:r.x+r.width/2,y:r.y+r.height/2}}; }})()"#,
        serde_json::to_string(selector).unwrap_or_else(|_| "\"\"".into())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_expression_embeds_css_selector() {
        let expression = build_evaluate_expression_for_selector("#login > button.primary");
        assert!(expression.contains("#login > button.primary"));
        assert!(expression.contains("getBoundingClientRect"));
    }

    #[test]
    fn browser_bus_stores_debugger_url() {
        let bus = BrowserBus::new("ws://127.0.0.1:9/devtools/page/abc");
        assert!(bus.debugger_url().contains("devtools/page/abc"));
    }
}
