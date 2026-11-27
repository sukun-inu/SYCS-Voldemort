//! 地震の電文の受け取りと気象庁の一覧の取得を、テストの中で立てた偽物に当てて確かめる。
//!
//! 受け取りは、本物の Python（`run_earthquake_ws`）と同じ偽物の WebSocket に両方を当てて、通知に回す
//! もの 11 件が一致することを確かめた（変更のコミットに記録）。ここではその流れを CI で毎回回す。
//!
//! 時間に頼るところは「いつかは起きる」「下限」だけを見る（CI は遅い）。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use sycs_bot::earthquake::{DetailUrls, JMA_FALLBACK_URL, NotifyType};
use sycs_bot::earthquake_feed::{FeedConfig, JmaDetailUrls, Kind, run_forever};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

/// 偽物の WebSocket の接続ごとのふるまい。
#[derive(Clone)]
enum Script {
    /// 文を順に送る。`close` なら送り終えたら切る、でなければ開いたまま（ping には応える）。
    Send { texts: Vec<String>, close: bool },
    /// 何も送らず、ping にも応えない（読まない）。
    Silent,
}

/// 偽物の WebSocket を立てる。`scripts` の順に接続を扱い、足りなくなったら最後のものを繰り返す。
/// 返すのは場所と、受けた接続の数。
async fn start_ws(scripts: Vec<Script>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let connections = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&connections);
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let n = count.fetch_add(1, Ordering::SeqCst);
            let script = scripts[n.min(scripts.len() - 1)].clone();
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(socket).await else {
                    return;
                };
                match script {
                    Script::Silent => {
                        // 読まないので、ping が来ても pong を返さない。
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        drop(ws);
                    }
                    Script::Send { texts, close } => {
                        for text in texts {
                            let message = if text == "__binary__" {
                                Message::Binary(vec![1, 2].into())
                            } else {
                                Message::Text(text.into())
                            };
                            if ws.send(message).await.is_err() {
                                return;
                            }
                        }
                        if close {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            let _ = ws.close(None).await;
                        }
                        // 読み続ける（ping が来たら pong を返す）。
                        while let Some(Ok(_)) = ws.next().await {}
                    }
                }
            });
        }
    });
    (url, connections)
}

fn config(url: &str) -> FeedConfig {
    FeedConfig {
        ws_url: url.into(),
        reconnect_delay: Duration::from_millis(50),
        ..FeedConfig::default()
    }
}

type Seen = Arc<Mutex<Vec<(Kind, Value)>>>;

/// 受け取りを動かして、通知に回したものを記録する。
fn spawn_feed(config: FeedConfig) -> (tokio::task::JoinHandle<()>, Seen) {
    let seen: Seen = Arc::default();
    let log = Arc::clone(&seen);
    let task = tokio::spawn(run_forever(config, move |kind, data| {
        let log = Arc::clone(&log);
        async move {
            log.lock().unwrap().push((kind, data["id"].clone()));
        }
    }));
    (task, seen)
}

/// 条件が成り立つまで待つ（最大 20 秒）。
async fn wait_until(what: &str, done: impl Fn() -> bool) {
    for _ in 0..400 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("20 秒待っても起きなかった: {what}");
}

fn texts(list: &[Value]) -> Vec<String> {
    list.iter()
        .map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .collect()
}

/// 4 つの種類だけを通知に回し、同じ id は 1 回だけ、つなぎ直しても覚えていること。Python と同じ 11 件。
#[tokio::test]
async fn events_are_filtered_and_deduplicated_across_reconnects() {
    let first = texts(&[
        json!({"code": 551, "id": "a", "earthquake": {}}),
        json!({"code": 555, "id": "p"}),
        json!("not json"),
        json!({"code": 551, "id": "a"}),
        json!({"code": 552, "id": "b"}),
        json!({"code": 554, "id": "c", "type": "Full"}),
        json!({"code": 556, "id": "d"}),
        json!({"code": 551}),
        json!({"code": 551, "id": ""}),
        json!({"code": 551, "id": 12345}),
        json!({"code": 552, "id": 12345}),
        json!({"code": "551", "id": "h"}),
        json!([551]),
    ]);
    let second = texts(&[
        json!({"code": 551, "id": "a"}),
        json!({"code": 551, "id": "e"}),
        json!("__binary__"),
        json!({"code": 552, "id": "b"}),
        json!({"code": 556, "id": "f", "cancelled": true}),
        json!({"code": 551.0, "id": "g"}),
        json!({"code": 561, "id": "z"}),
        json!({"code": 554, "id": "h"}),
    ]);
    let (url, connections) = start_ws(vec![
        Script::Send {
            texts: first,
            close: true,
        },
        Script::Send {
            texts: second,
            close: false,
        },
    ])
    .await;
    let (task, seen) = spawn_feed(config(&url));
    wait_until("11 件の通知", || seen.lock().unwrap().len() >= 11).await;
    // 余分なものが遅れて来ないことも見る。
    tokio::time::sleep(Duration::from_millis(300)).await;
    task.abort();
    let mut got: Vec<(String, String)> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|(kind, id)| {
            let name = match kind {
                Kind::Quake => "quake",
                Kind::Tsunami => "tsunami",
                Kind::Eew(NotifyType::EewForecast) => "eew_forecast",
                Kind::Eew(_) => "eew_warning",
            };
            (name.to_string(), id.to_string())
        })
        .collect();
    got.sort();
    let want: Vec<(String, String)> = [
        ("eew_forecast", "\"d\""),
        ("eew_forecast", "\"f\""),
        ("eew_warning", "\"c\""),
        ("eew_warning", "\"h\""),
        ("quake", "\"\""),
        ("quake", "\"a\""),
        ("quake", "\"e\""),
        ("quake", "\"g\""),
        ("quake", "12345"),
        ("quake", "null"),
        ("tsunami", "\"b\""),
    ]
    .iter()
    .map(|(k, id)| (k.to_string(), id.to_string()))
    .collect();
    assert_eq!(got, want);
    assert_eq!(
        connections.load(Ordering::SeqCst),
        2,
        "切れたあとにつなぎ直していない"
    );
}

/// 何も届かず ping にも応えがなければ、切れたとみなしてつなぎ直すこと。
#[tokio::test]
async fn a_silent_connection_is_dropped_and_reconnected() {
    let (url, connections) = start_ws(vec![Script::Silent]).await;
    let (task, _seen) = spawn_feed(FeedConfig {
        heartbeat: Duration::from_millis(100),
        pong_wait: Duration::from_millis(100),
        ..config(&url)
    });
    wait_until("つなぎ直し", || {
        connections.load(Ordering::SeqCst) >= 2
    })
    .await;
    task.abort();
}

/// ping に応えがある間は、何も届かなくてもつないだままにすること。
#[tokio::test]
async fn a_quiet_but_alive_connection_is_kept() {
    let (url, connections) = start_ws(vec![Script::Send {
        texts: Vec::new(),
        close: false,
    }])
    .await;
    // 応えを待つ時間は長めに取る（遅い環境で pong が遅れても切らないように）。
    let (task, _seen) = spawn_feed(FeedConfig {
        heartbeat: Duration::from_millis(100),
        pong_wait: Duration::from_secs(30),
        ..config(&url)
    });
    // ping を何度か送る間、待つ。
    tokio::time::sleep(Duration::from_millis(1200)).await;
    task.abort();
    assert_eq!(connections.load(Ordering::SeqCst), 1);
}

/// つなげないときは、待ってからつなぎ直し続けること（落ちない）。
#[tokio::test]
async fn a_refused_connection_is_retried() {
    // いったん立ててすぐ閉じた場所（つなげない）。
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    drop(listener);
    let (task, seen) = spawn_feed(config(&url));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!task.is_finished(), "つなげないだけで受け取りが終わった");
    assert!(seen.lock().unwrap().is_empty());
    task.abort();
}

/// wss:// でも、暗号の準備で落ちないこと（相手が TLS を話さないので失敗にはなる）。
///
/// rustls は暗号の実装を 1 つ選んでおかないと、つなぐ瞬間に落ちる。本番の相手は wss:// なので、
/// ここで確かめておく。
#[tokio::test]
async fn tls_setup_does_not_panic() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("wss://{}/ws", listener.local_addr().unwrap());
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let _ = socket.write_all(b"not tls").await;
        }
    });
    let result = tokio_tungstenite::connect_async(url.as_str()).await;
    assert!(result.is_err());
}

/// 偽物の気象庁（一覧の JSON を返す）。返すのは場所と、受けた要求の数。`bodies` を順に返し、
/// 足りなくなったら最後のものを繰り返す。
async fn start_jma(bodies: Vec<(u16, String)>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/list.json", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let n = count.fetch_add(1, Ordering::SeqCst);
            let (status, body) = bodies[n.min(bodies.len() - 1)].clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut read = Vec::new();
                while !read.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => read.extend_from_slice(&buf[..n]),
                    }
                }
                // 種類は JSON と書かない（Python は種類を見ずに読む）。
                let head = format!(
                    "HTTP/1.1 {status} X\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(body.as_bytes()).await;
            });
        }
    });
    (url, hits)
}

fn quake() -> Value {
    json!({
        "code": 551,
        "earthquake": {
            "time": "2026/08/24 12:54:41",
            "hypocenter": {"name": "茨城県沖", "magnitude": 5.2},
        },
        "points": [{"pref": "茨城県", "scale": 40}],
    })
}

fn listing(eid: &str) -> String {
    json!([{"eid": eid, "at": "2026-08-24T12:54:00+09:00", "anm": "茨城県沖", "mag": "5.2"}])
        .to_string()
}

/// 一覧は 30 秒のあいだ取り直さないこと。取った一覧からリンクを決めること。
#[tokio::test]
async fn the_list_is_fetched_once_and_reused() {
    let (url, hits) = start_jma(vec![(200, listing("E1")), (200, listing("E2"))]).await;
    let jma = JmaDetailUrls::new(&url);
    assert_eq!(jma.list().await.len(), 1);
    assert_eq!(jma.list().await.len(), 1);
    assert_eq!(hits.load(Ordering::SeqCst), 1, "30 秒たたずに取り直した");
    assert_eq!(
        jma.resolve(&quake(), 40).await,
        "https://www.jma.go.jp/bosai/map.html?contents=earthquake_map&id=E1"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

/// 決めたリンクは覚えておくこと（一覧が変わっても、同じ地震には同じリンク）。別の地震は決め直すこと。
#[tokio::test]
async fn resolved_urls_are_remembered_per_quake() {
    let (url, hits) = start_jma(vec![(200, listing("E1")), (200, listing("E2"))]).await;
    // 一覧は毎回取り直させる。
    let jma = JmaDetailUrls::with_list_ttl(&url, 0.0);
    let first = jma.resolve(&quake(), 40).await;
    assert!(first.ends_with("id=E1"), "{first}");
    assert_eq!(jma.resolve(&quake(), 40).await, first);
    assert_eq!(hits.load(Ordering::SeqCst), 1, "覚えたリンクを使わなかった");
    // 最大震度が違えば別の鍵。
    let other = jma.resolve(&quake(), 45).await;
    assert!(other.ends_with("id=E2"), "{other}");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

/// 取れなかった（200 以外・JSON でない・配列でない）ときは、前に取ったものを使うこと。無ければ空で、
/// リンクは統合地図のページになること。
#[tokio::test]
async fn a_failed_fetch_falls_back_to_the_previous_list() {
    let (url, hits) = start_jma(vec![
        // 200 以外は、中身が正しい一覧でも使わない。
        (500, listing("BAD")),
        (200, "{\"not\": \"a list\"}".into()),
        (200, "not json".into()),
        (200, listing("E1")),
        (503, "down".into()),
        (200, "{}".into()),
    ])
    .await;
    let jma = JmaDetailUrls::with_list_ttl(&url, 0.0);
    for _ in 0..3 {
        assert!(jma.list().await.is_empty());
    }
    // 4 回目は取れる。
    assert_eq!(
        jma.resolve(&quake(), 40).await,
        "https://www.jma.go.jp/bosai/map.html?contents=earthquake_map&id=E1"
    );
    // 5・6 回目は取れないので、4 回目のものを使う（配列でないものを覚えていない）。
    assert_eq!(jma.list().await[0]["eid"], "E1");
    assert_eq!(jma.list().await[0]["eid"], "E1");
    assert_eq!(hits.load(Ordering::SeqCst), 6);
    // 何も取れなければ統合地図のページ。
    let (url, _) = start_jma(vec![(404, listing("BAD"))]).await;
    let jma = JmaDetailUrls::with_list_ttl(&url, 0.0);
    assert_eq!(jma.resolve(&quake(), 40).await, JMA_FALLBACK_URL);
}

/// 同時に取りに行っても、要求は 1 本にまとめること。
#[tokio::test]
async fn concurrent_callers_share_one_fetch() {
    let (url, hits) = start_jma(vec![(200, listing("E1"))]).await;
    let jma = Arc::new(JmaDetailUrls::new(&url));
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let jma = Arc::clone(&jma);
        set.spawn(async move { jma.list().await.len() });
    }
    while let Some(n) = set.join_next().await {
        assert_eq!(n.unwrap(), 1);
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}
