//! serenity + songbird の Bot が、DAVE 必須の VC で音を届けられるかを人の耳で確かめる道具。
//!
//! `/voice-test delay_ms:<ミリ秒>` を打った人の VC に入り、delay_ms 待ってから
//! 低・中・高の「ピッ」を 3 回鳴らして抜ける。聞いた人が「何回聞こえたか」を
//! 答えれば、入ってすぐの音が捨てられていないか（songbird #310）が分かる。
//!
//! ■ なぜ人の耳で確かめるのか
//!
//! Discord は 2026-03-02 からボットにも音声のエンドツーエンド暗号化（DAVE）を
//! 必須にした。暗号化されていない音声は、受け取った端末が黙って捨てる。songbird は
//! DAVE の鍵交換に成功しても何もログに出さず、#310 の症状（準備前の音が暗号化
//! されずに出ていく）でもログは出ない。**ログからは「届いた」と言えない。**
//!
//! ■ 使い方と過去の結果
//!
//! rust/tools/voice-check/README.ja.md。serenity・songbird・davey を上げたときは、
//! 本番へ出す前に必ずこれで確かめる。
//!
//! 環境変数:
//!   DISCORD_BOT_TOKEN  試験用アプリのトークン（**本番の Bot のものは使わない**）
//!   TEST_GUILD_ID      コマンドを登録する試験用サーバーの ID
//!   RUST_LOG           既定は "info,songbird=debug,voice_check=debug"

use std::{env, process, time::Duration};

use serenity::{
    Client,
    all::{
        ChannelId, CommandDataOptionValue, CommandInteraction, CommandOptionType, Context,
        CreateCommand, CreateCommandOption, EditInteractionResponse, EventHandler, GatewayIntents,
        GuildId, Interaction, Ready,
    },
    async_trait,
};
use songbird::{SerenityInit, input::Input};
use tracing::{error, info, warn};

/// 試験用アプリが入っていてよいサーバーの数。
///
/// 本番の Bot は多くのサーバーに入っている。トークンを取り違えて本番の Bot で
/// 動かすと、本番のサーバーに試験用のコマンドが載り、VC へ勝手に入る。入っている
/// サーバーが 1 つより多ければ、何もせずに止まる。
const MAX_GUILDS: usize = 1;

/// 鳴らし終わるまでの待ち。3 回 × (0.3 秒 + 0.4 秒) = 2.1 秒に余裕を足す。
const PLAY_WAIT: Duration = Duration::from_millis(2_600);

/// 48 kHz・モノラル・16 bit の WAV を組み立てる。
///
/// ファイルを持ち込まずに済むよう、音はその場で合成する。高さを 3 回で変えるのは、
/// 「最初の 1 回だけ聞こえなかった」を聞いた人が言い分けられるようにするため
/// （#310 の症状は最初の数百ミリ秒が欠ける形で出る）。
fn beeps_wav() -> Vec<u8> {
    const RATE: u32 = 48_000;
    let tone = RATE as usize * 3 / 10;
    let gap = RATE as usize * 4 / 10;
    let mut samples: Vec<i16> = Vec::with_capacity((tone + gap) * 3);
    for freq in [440.0_f32, 660.0, 880.0] {
        for n in 0..tone {
            let t = n as f32 / RATE as f32;
            samples.push(((t * freq * std::f32::consts::TAU).sin() * 12_000.0) as i16);
        }
        samples.extend(std::iter::repeat_n(0, gap));
    }
    let data_len = (samples.len() * 2) as u32;
    let mut wav = Vec::with_capacity(44 + data_len as usize);
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&(36 + data_len).to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes()); // PCM
    wav.extend_from_slice(&1u16.to_le_bytes()); // モノラル
    wav.extend_from_slice(&RATE.to_le_bytes());
    wav.extend_from_slice(&(RATE * 2).to_le_bytes());
    wav.extend_from_slice(&2u16.to_le_bytes());
    wav.extend_from_slice(&16u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&data_len.to_le_bytes());
    for s in samples {
        wav.extend_from_slice(&s.to_le_bytes());
    }
    wav
}

/// コマンドを打った人がいま入っている VC。キャッシュの voice_states から引く。
fn caller_voice_channel(ctx: &Context, cmd: &CommandInteraction) -> Option<ChannelId> {
    let guild = ctx.cache.guild(cmd.guild_id?)?;
    guild.voice_states.get(&cmd.user.id)?.channel_id
}

/// `delay_ms` の値。省略されたら 0（入ってすぐ鳴らす。#310 がいちばん出やすい形）。
fn delay_option(cmd: &CommandInteraction) -> u64 {
    cmd.data
        .options
        .iter()
        .find(|o| o.name == "delay_ms")
        .and_then(|o| match o.value {
            CommandDataOptionValue::Integer(v) => u64::try_from(v).ok(),
            _ => None,
        })
        .unwrap_or(0)
}

/// VC に入り、待ち、鳴らし、抜ける。時刻はすべてログに残す。
///
/// 聞こえなかったと言われたとき、join から鳴らし始めるまでに何ミリ秒あったかが
/// 切り分けの手がかりになる。
async fn run_test(ctx: &Context, cmd: &CommandInteraction) -> Result<String, String> {
    let guild_id = cmd.guild_id.ok_or("サーバーの中で打ってください")?;
    let channel_id = caller_voice_channel(ctx, cmd).ok_or("先に VC に入ってから打ってください")?;
    let delay = delay_option(cmd);
    let manager = songbird::get(ctx)
        .await
        .ok_or("songbird が登録されていない")?;

    let started = std::time::Instant::now();
    info!(%guild_id, %channel_id, delay, "VC に入る");
    let call = manager
        .join(guild_id, channel_id)
        .await
        .map_err(|e| format!("VC に入れなかった: {e:?}"))?;
    info!(
        elapsed_ms = started.elapsed().as_millis() as u64,
        "join が返った"
    );

    tokio::time::sleep(Duration::from_millis(delay)).await;
    let track = {
        let mut handler = call.lock().await;
        info!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            "鳴らし始める"
        );
        handler.play_input(Input::from(beeps_wav()))
    };
    tokio::time::sleep(PLAY_WAIT).await;
    // 鳴り終わっていれば Finished が返る。それが正常（再生中のままなら長すぎる）。
    match track.get_info().await {
        Ok(state) => warn!(playing = ?state.playing, "まだ再生中だった"),
        Err(e) => info!(?e, "再生は終わっている"),
    }
    if let Err(e) = manager.remove(guild_id).await {
        warn!(?e, "VC から抜けられなかった");
    }
    info!(elapsed_ms = started.elapsed().as_millis() as u64, "抜けた");
    Ok(format!(
        "delay_ms={delay} で鳴らしました。低・中・高の 3 回のうち、何回聞こえましたか？"
    ))
}

/// Discord からのイベントを受ける。登録するサーバーは起動時に決めた 1 つだけ。
struct Handler {
    guild_id: GuildId,
}

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        info!(user = %ready.user.name, guilds = ready.guilds.len(), "接続した");
        if ready.guilds.len() > MAX_GUILDS {
            error!(
                guilds = ready.guilds.len(),
                "{MAX_GUILDS} つより多いサーバーに入っている Bot では動かさない（本番のトークンでないか確かめること）"
            );
            process::exit(2);
        }
        // グローバルのコマンドには触らない。間違って本番のトークンで動かしたとき、
        // 本番の Bot のコマンドを消してしまうため。登録は試験用サーバーにだけ行う。
        let command = CreateCommand::new("voice-test")
            .description("VC に入って 3 回鳴らす（DAVE の試験）")
            .add_option(
                CreateCommandOption::new(
                    CommandOptionType::Integer,
                    "delay_ms",
                    "入ってから鳴らすまで待つミリ秒（既定 0）",
                )
                .min_int_value(0)
                .max_int_value(10_000),
            );
        match self.guild_id.set_commands(&ctx.http, vec![command]).await {
            Ok(_) => info!(guild_id = %self.guild_id, "/voice-test を登録した"),
            Err(e) => error!(?e, "コマンドを登録できなかった"),
        }
    }

    async fn interaction_create(&self, ctx: Context, interaction: Interaction) {
        let Interaction::Command(cmd) = interaction else {
            return;
        };
        if cmd.data.name != "voice-test" {
            return;
        }
        // VC に入って鳴らし終わるまで 3 秒を超えるので、先に「考え中」を返す。
        // 返さないと Discord 側で「アプリケーションが応答しませんでした」になる。
        if let Err(e) = cmd.defer(&ctx.http).await {
            error!(?e, "応答を保留できなかった");
            return;
        }
        let message = match run_test(&ctx, &cmd).await {
            Ok(text) => text,
            Err(text) => {
                warn!(%text, "試験を中断した");
                text
            }
        };
        if let Err(e) = cmd
            .edit_response(&ctx.http, EditInteractionResponse::new().content(message))
            .await
        {
            warn!(?e, "結果を返せなかった");
        }
    }
}

/// 環境変数を読み、Bot を起動する。Ctrl+C で止まる。
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            env::var("RUST_LOG").unwrap_or_else(|_| "info,songbird=debug,voice_check=debug".into()),
        )
        .init();

    let Ok(token) = env::var("DISCORD_BOT_TOKEN") else {
        error!("DISCORD_BOT_TOKEN が無い");
        process::exit(1);
    };
    let Some(guild_id) = env::var("TEST_GUILD_ID")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v != 0)
        .map(GuildId::new)
    else {
        error!("TEST_GUILD_ID が無いか、数字でない");
        process::exit(1);
    };

    let intents = GatewayIntents::GUILDS | GatewayIntents::GUILD_VOICE_STATES;
    let mut client = match Client::builder(&token, intents)
        .event_handler(Handler { guild_id })
        .register_songbird()
        .await
    {
        Ok(client) => client,
        Err(e) => {
            error!(?e, "クライアントを作れなかった");
            process::exit(1);
        }
    };

    let shard_manager = client.shard_manager.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        shard_manager.shutdown_all().await;
    });
    if let Err(e) = client.start().await {
        error!(?e, "クライアントが止まった");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use symphonia::core::{
        audio::SampleBuffer, codecs::DecoderOptions, formats::FormatOptions, io::MediaSourceStream,
        meta::MetadataOptions, probe::Hint,
    };

    use super::beeps_wav;

    /// 合成した WAV を、songbird と同じ復号器（symphonia）で最後まで読み、
    /// 48 kHz・モノラルで 2.1 秒ぶんの音が出てくること。
    ///
    /// ヘッダの長さを 1 か所でも間違えると、songbird は読めずに無音で終わる。
    /// **この道具では、無音は「DAVE で捨てられた（#310）」と見分けが付かない。**
    /// 壊れた WAV のまま試験すると、songbird の不具合だと誤って結論づける。
    #[test]
    fn the_beeps_decode_to_three_tones_of_audible_length() {
        let source = MediaSourceStream::new(Box::new(Cursor::new(beeps_wav())), Default::default());
        let mut hint = Hint::new();
        hint.with_extension("wav");
        let probed = symphonia::default::get_probe()
            .format(
                &hint,
                source,
                &FormatOptions::default(),
                &MetadataOptions::default(),
            )
            .expect("WAV として読めない");
        let mut format = probed.format;
        let track = format
            .default_track()
            .expect("音声のトラックが無い")
            .clone();
        assert_eq!(track.codec_params.sample_rate, Some(48_000));
        assert_eq!(track.codec_params.channels.map(|c| c.count()), Some(1));

        let mut decoder = symphonia::default::get_codecs()
            .make(&track.codec_params, &DecoderOptions::default())
            .expect("復号器を作れない");
        let mut frames = 0usize;
        let mut loudest = 0.0f32;
        while let Ok(packet) = format.next_packet() {
            let decoded = decoder.decode(&packet).expect("復号できない");
            let mut buf = SampleBuffer::<f32>::new(decoded.capacity() as u64, *decoded.spec());
            buf.copy_interleaved_ref(decoded);
            frames += buf.samples().len();
            loudest = buf.samples().iter().fold(loudest, |m, s| m.max(s.abs()));
        }
        // 3 回 × (0.3 秒の音 + 0.4 秒の間) = 2.1 秒 = 100,800 サンプル。
        assert_eq!(frames, 100_800);
        // 無音ではないこと（振幅 12,000 / 32,768 ≒ 0.37）。
        assert!(loudest > 0.3, "音が小さすぎる: {loudest}");
    }
}
