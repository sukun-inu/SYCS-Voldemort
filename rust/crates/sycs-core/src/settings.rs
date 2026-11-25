//! ギルドごとの設定を Postgres から読む。Python の `services/settings_pg.py` と同じ表・同じ合図。
//!
//! 移行中は Python（管理画面）が設定を書き、Rust（Bot）が読む。表の形と、変わったことの
//! 知らせ方を揃えておけば、どちらの言語が書いても、もう片方に数十ミリ秒で届く。
//!
//! | 表 | 中身 |
//! |---|---|
//! | `bot_settings_guild` | ギルドごとに 1 行（`guild_key` 文字列, `data` JSONB） |
//! | `bot_settings_state` | 1 行だけ（`id = 1`）。`version`（書くたびに 1 増える）と `root`（guilds 以外のキー） |
//!
//! 読み込みは全体をメモリに持つ（設定はメッセージのたびに読まれるので、毎回 Postgres へ
//! 行くと往復のぶん処理が止まる）。新しく保つ合図は Python と同じく 2 つ。
//!
//! - `LISTEN bot_settings_changed`: 書いた側がコミットと同時に版番号を流す。受けたら、
//!   手元より新しければ読み直す。接続が切れたら sqlx がつなぎ直し、その間の分を読み直す
//! - 版番号の確認: 一定の間隔で版番号だけを見る（LISTEN を取りこぼしたときの保険）
//!
//! 書き込みはまだ無い（Bot を移す塊で足す）。書き込みは null を落とすことと「最後に
//! 触られた時刻」を押すことまで Python の `_mutate_settings` と揃える必要がある。
//!
//! 表を作るのは今は Python 側（最初に使ったときに作る）。Rust は表がある前提で読む。

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde_json::{Map, Value};
use sqlx::PgPool;
use sqlx::postgres::PgListener;
use tracing::{debug, info, warn};

/// 変更を知らせる通知の名前。Python の `settings_pg.CHANNEL`。
pub const CHANNEL: &str = "bot_settings_changed";

/// ある時点の設定の全体。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Settings {
    /// 版番号。書かれるたびに 1 増える。表が空なら 0。
    pub version: i64,
    /// guilds 以外のトップレベルのキー。
    pub root: Map<String, Value>,
    /// ギルドの鍵（数字の文字列）→ そのギルドの設定。
    pub guilds: BTreeMap<String, Value>,
}

impl Settings {
    /// 1 ギルドの設定。無ければ `None`（「未設定」として既定値を使うこと）。
    pub fn guild(&self, guild_id: u64) -> Option<&Value> {
        self.guilds.get(&guild_id.to_string())
    }
}

/// 全体を 1 回読む。
pub async fn load(pool: &PgPool) -> Result<Settings, sqlx::Error> {
    let state: Option<(i64, Value)> =
        sqlx::query_as("SELECT version, root FROM bot_settings_state WHERE id = 1")
            .fetch_optional(pool)
            .await?;
    let rows: Vec<(String, Value)> =
        sqlx::query_as("SELECT guild_key, data FROM bot_settings_guild")
            .fetch_all(pool)
            .await?;
    let (version, root) = match state {
        Some((version, Value::Object(root))) => (version, root),
        Some((version, _)) => (version, Map::new()),
        None => (0, Map::new()),
    };
    Ok(Settings {
        version,
        root,
        guilds: rows.into_iter().collect(),
    })
}

/// 手元に持っている設定。読むのはロック 1 つと参照の複製だけで、Postgres へは行かない。
pub struct SettingsCache {
    pool: PgPool,
    current: RwLock<Arc<Settings>>,
}

impl SettingsCache {
    /// 最初の読み込みをして、通知の受け取りと版番号の確認を動かし始める。
    ///
    /// **最初に読めなければエラーを返す。** 空の設定で動き出すと、セキュリティ機能が全部
    /// 切れたように振る舞い、誰も気づかない（Python も空では動かない）。読めないときに
    /// 待つかやめるかは呼び出し側が決める。
    pub async fn start(pool: PgPool, poll_interval: Duration) -> Result<Arc<Self>, sqlx::Error> {
        Self::start_with(pool, poll_interval, true).await
    }

    /// [`SettingsCache::start`] と同じだが、`listen` が偽なら LISTEN を張らず、版番号の確認だけで追う。
    ///
    /// LISTEN が使えない接続（PgBouncer の transaction モードなど）のための口。テストでも、
    /// 版番号の確認が効いていることを LISTEN と切り離して確かめるのに使う（通知はデータベース
    /// 全体に届くので、他のテストの通知で読み直してしまい、確認の効き目を見分けられない）。
    pub async fn start_with(
        pool: PgPool,
        poll_interval: Duration,
        listen: bool,
    ) -> Result<Arc<Self>, sqlx::Error> {
        let initial = load(&pool).await?;
        info!(
            guilds = initial.guilds.len(),
            version = initial.version,
            "Postgres から設定を読み込みました"
        );
        let cache = Arc::new(Self {
            pool,
            current: RwLock::new(Arc::new(initial)),
        });
        if listen {
            tokio::spawn(Arc::clone(&cache).listen_forever());
        }
        tokio::spawn(Arc::clone(&cache).poll_forever(poll_interval.max(Duration::from_secs(1))));
        Ok(cache)
    }

    /// いまの設定。返すのは読み込んだ時点の写しで、あとから変わらない。
    pub fn snapshot(&self) -> Arc<Settings> {
        Arc::clone(&self.current.read().unwrap_or_else(|p| p.into_inner()))
    }

    /// 手元の版番号。
    pub fn version(&self) -> i64 {
        self.snapshot().version
    }

    /// 手元より新しい版があれば、読み直して差し替える。`hint` は通知で届いた版番号。
    pub async fn refresh_if_newer(&self, hint: Option<i64>) {
        let current = self.version();
        if hint.is_some_and(|v| v <= current) {
            return;
        }
        match load(&self.pool).await {
            Ok(fresh) if fresh.version > current => {
                debug!(
                    from = current,
                    to = fresh.version,
                    "他のプロセスの変更を読み直しました"
                );
                let mut guard = self.current.write().unwrap_or_else(|p| p.into_inner());
                // 読んでいる間に、もっと新しい版が入っていたら戻さない。
                if fresh.version > guard.version {
                    *guard = Arc::new(fresh);
                }
            }
            Ok(_) => {}
            Err(e) => warn!("設定を読み直せませんでした（手元の設定で続けます）: {e}"),
        }
    }

    async fn listen_forever(self: Arc<Self>) {
        let mut delay = Duration::from_secs(1);
        loop {
            match self.listen_once().await {
                Ok(()) => delay = Duration::from_secs(1),
                Err(e) => warn!(
                    "設定の変更の通知を受けられません（{} 秒後につなぎ直します）: {e}",
                    delay.as_secs()
                ),
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(60));
        }
    }

    /// つないで聞き続ける。返ってくるのはエラーのときだけ。
    async fn listen_once(&self) -> Result<(), sqlx::Error> {
        let mut listener = PgListener::connect_with(&self.pool).await?;
        listener.listen(CHANNEL).await?;
        // つないでいなかった間の書き込みを拾う。
        self.refresh_if_newer(None).await;
        loop {
            match listener.try_recv().await? {
                Some(notification) => {
                    self.refresh_if_newer(notification.payload().parse().ok())
                        .await;
                }
                // 接続が切れた。sqlx が次の呼び出しでつなぎ直して LISTEN し直す。切れていた
                // 間の通知は届かないので、ここで読み直して追いつく。
                None => self.refresh_if_newer(None).await,
            }
        }
    }

    async fn poll_forever(self: Arc<Self>, interval: Duration) {
        loop {
            tokio::time::sleep(interval).await;
            let row: Result<Option<(i64,)>, _> =
                sqlx::query_as("SELECT version FROM bot_settings_state WHERE id = 1")
                    .fetch_optional(&self.pool)
                    .await;
            match row {
                Ok(Some((version,))) => self.refresh_if_newer(Some(version)).await,
                Ok(None) => {}
                Err(e) => {
                    warn!("設定の版番号を確かめられませんでした（手元の設定で続けます）: {e}")
                }
            }
        }
    }
}
