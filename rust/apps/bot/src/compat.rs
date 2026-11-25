//! discord.py と同じ見た目の文字列を作る（`str(user)`・`display_avatar.url`・`mention`）。
//!
//! 移行の途中で Python と Rust の Bot が並び、どちらもログチャンネルへ書く。名前の出し方や
//! アバターの URL が違うと、同じ人のログが 2 通りの見た目で並ぶ。さらにアバターの URL は
//! 代表色（ログの Embed の色）を取る元なので、**形式まで同じでないと色が変わる。** serenity の
//! `face()` は webp（非可逆）を返すが、discord.py は png を返す。復号した画素が変わり、
//! 代表色がずれるので、ここで discord.py と同じ URL を組み立てる。
//!
//! 一致は、同じ Discord の JSON を discord.py と serenity に読ませて突き合わせて確かめた
//! （変更のコミットに記録）。

use serenity::all::{GuildId, ImageHash, Member, User, UserId};

/// Discord の CDN。discord.py の `Asset.BASE`。
pub const CDN: &str = "https://cdn.discordapp.com";

/// `str(user)`。discord.py 2.x は、識別番号が無い（新しいユーザー名の）人は名前だけ、
/// ある人（Bot など）は `名前#1234`。
pub fn user_tag(user: &User) -> String {
    match user.discriminator {
        Some(d) => format!("{}#{:04}", user.name, d.get()),
        None => user.name.clone(),
    }
}

/// `user.mention`（`<@ユーザーID>`）。discord.py 2.x は `!` を付けない。
pub fn mention(user_id: UserId) -> String {
    format!("<@{user_id}>")
}

/// `user.display_avatar.url`。アバターが無ければ既定のアバター。
pub fn user_avatar_url(user: &User) -> String {
    match &user.avatar {
        Some(hash) => asset_url(&format!("avatars/{}", user.id), hash),
        None => default_avatar_url(user),
    }
}

/// `member.display_avatar.url`。サーバーごとのアバターがあればそれ、無ければユーザーのもの。
pub fn member_avatar_url(member: &Member) -> String {
    match &member.avatar {
        Some(hash) => guild_avatar_url(member.guild_id, member.user.id, hash),
        None => user_avatar_url(&member.user),
    }
}

fn guild_avatar_url(guild_id: GuildId, user_id: UserId, hash: &ImageHash) -> String {
    asset_url(&format!("guilds/{guild_id}/users/{user_id}/avatars"), hash)
}

/// discord.py の `Asset._from_avatar`: 動くもの（`a_` で始まる）は gif、それ以外は png。大きさは 1024。
fn asset_url(prefix: &str, hash: &ImageHash) -> String {
    let format = if hash.is_animated() { "gif" } else { "png" };
    format!("{CDN}/{prefix}/{hash}.{format}?size=1024")
}

/// discord.py の `default_avatar`: 識別番号が無ければ `(id >> 22) % 6`、あれば `番号 % 5`。
fn default_avatar_url(user: &User) -> String {
    let index = match user.discriminator {
        Some(d) => u64::from(d.get()) % 5,
        None => (user.id.get() >> 22) % 6,
    };
    format!("{CDN}/embed/avatars/{index}.png")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn user(extra: serde_json::Value) -> User {
        let mut data = json!({
            "id": "80351110224678912",
            "username": "nelly",
            "discriminator": "0",
            "avatar": null,
            "global_name": null,
        });
        data.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(data).unwrap()
    }

    /// 識別番号が無ければ名前だけ、あれば 4 桁で付けること。
    #[test]
    fn the_tag_matches_str_user() {
        assert_eq!(user_tag(&user(json!({}))), "nelly");
        assert_eq!(
            user_tag(&user(json!({"discriminator": "0042"}))),
            "nelly#0042"
        );
    }

    /// 静止画は png、動くものは gif で、大きさ 1024 を付けること（serenity の face() は webp）。
    #[test]
    fn avatars_are_png_or_gif_like_discord_py() {
        let still = user(json!({"avatar": "8342729096ea3675442027381ff50dfe"}));
        assert_eq!(
            user_avatar_url(&still),
            "https://cdn.discordapp.com/avatars/80351110224678912/8342729096ea3675442027381ff50dfe.png?size=1024"
        );
        let moving = user(json!({"avatar": "a_8342729096ea3675442027381ff50dfe"}));
        assert!(
            user_avatar_url(&moving).ends_with("/a_8342729096ea3675442027381ff50dfe.gif?size=1024")
        );
    }

    /// アバターが無ければ既定のアバター（番号の決め方は識別番号の有無で変わる）。
    #[test]
    fn the_default_avatar_index_follows_discord_py() {
        // (80351110224678912 >> 22) % 6
        let expected = (80_351_110_224_678_912_u64 >> 22) % 6;
        assert_eq!(
            user_avatar_url(&user(json!({}))),
            format!("https://cdn.discordapp.com/embed/avatars/{expected}.png")
        );
        assert_eq!(
            user_avatar_url(&user(json!({"discriminator": "0007"}))),
            "https://cdn.discordapp.com/embed/avatars/2.png"
        );
    }

    /// サーバーごとのアバターがあればそれ、無ければユーザーのアバターを使うこと。
    #[test]
    fn a_member_avatar_prefers_the_guild_one() {
        let member = |avatar: serde_json::Value| -> Member {
            serde_json::from_value(json!({
                "guild_id": "1399617700363370556",
                "user": {"id": "80351110224678912", "username": "nelly", "discriminator": "0",
                         "avatar": "8342729096ea3675442027381ff50dfe", "global_name": null},
                "avatar": avatar, "roles": [], "joined_at": "2026-01-01T00:00:00+00:00",
                "deaf": false, "mute": false, "flags": 0,
            }))
            .unwrap()
        };
        assert_eq!(
            member_avatar_url(&member(json!("fedcba9876543210fedcba9876543210"))),
            "https://cdn.discordapp.com/guilds/1399617700363370556/users/80351110224678912/avatars/fedcba9876543210fedcba9876543210.png?size=1024"
        );
        assert_eq!(
            member_avatar_url(&member(serde_json::Value::Null)),
            "https://cdn.discordapp.com/avatars/80351110224678912/8342729096ea3675442027381ff50dfe.png?size=1024"
        );
    }

    #[test]
    fn mentions_have_no_exclamation_mark() {
        assert_eq!(mention(UserId::new(42)), "<@42>");
    }
}
