//! コマンドを打った人の権限。Python の `commands/guards.py`（`ensure_admin`）と、discord.py の
//! `Member.guild_permissions.administrator` の決め方。

use std::collections::HashMap;

use serenity::all::{GuildId, Role, RoleId, UserId};

use super::reply::{NOT_ADMIN, NOT_IN_GUILD};

/// サーバーの管理者か。discord.py の `member.guild_permissions.administrator`。
///
/// サーバーの持ち主は常に管理者。それ以外は、持っているロール（サーバーにあるものだけ）と @everyone の
/// どれかに管理者の権限があれば管理者。
pub fn is_administrator(
    owner_id: UserId,
    user_id: UserId,
    member_roles: &[RoleId],
    guild_roles: &HashMap<RoleId, Role>,
    guild_id: GuildId,
) -> bool {
    if owner_id == user_id {
        return true;
    }
    let everyone = RoleId::new(guild_id.get());
    member_roles
        .iter()
        .chain(std::iter::once(&everyone))
        .filter_map(|id| guild_roles.get(id))
        .any(|role| role.permissions.administrator())
}

/// 打った人の立場。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// サーバーの外（DM など）。
    OutsideGuild,
    /// サーバーの中の、管理者でない人。
    Member,
    /// サーバーの管理者。
    Admin,
}

/// 管理者でなければ、断る文言を返す。Python の `ensure_admin`。
pub fn refusal_for_admin_only(standing: Standing) -> Option<&'static str> {
    match standing {
        Standing::OutsideGuild => Some(NOT_IN_GUILD),
        Standing::Member => Some(NOT_ADMIN),
        Standing::Admin => None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const GUILD: u64 = 1;

    fn role(id: u64, permissions: u64) -> (RoleId, Role) {
        let role: Role = serde_json::from_value(json!({
            "id": id.to_string(), "name": format!("r{id}"), "color": 0,
            "colors": {"primary_color": 0, "secondary_color": null, "tertiary_color": null},
            "hoist": false, "position": 1, "permissions": permissions.to_string(),
            "managed": false, "mentionable": false, "flags": 0, "guild_id": GUILD.to_string(),
        }))
        .unwrap();
        (RoleId::new(id), role)
    }

    const ADMINISTRATOR: u64 = 1 << 3;
    const MANAGE_GUILD: u64 = 1 << 5;

    /// 持ち主・管理者のロール・@everyone の管理者の権限のどれかで管理者。無いロールは数えない。
    #[test]
    fn administrators_are_owners_or_hold_an_admin_role() {
        let roles: HashMap<RoleId, Role> = [
            role(GUILD, 0),
            role(10, ADMINISTRATOR),
            role(11, MANAGE_GUILD),
        ]
        .into();
        let g = GuildId::new(GUILD);
        let check = |owner: u64, user: u64, held: &[u64]| {
            let held: Vec<RoleId> = held.iter().map(|&r| RoleId::new(r)).collect();
            is_administrator(UserId::new(owner), UserId::new(user), &held, &roles, g)
        };
        assert!(check(5, 5, &[]), "持ち主");
        assert!(check(5, 6, &[11, 10]));
        assert!(!check(5, 6, &[11]), "サーバーの管理（管理者ではない）");
        assert!(!check(5, 6, &[]));
        assert!(!check(5, 6, &[999]), "サーバーに無いロール");
        let everyone_admin: HashMap<RoleId, Role> = [role(GUILD, ADMINISTRATOR)].into();
        assert!(is_administrator(
            UserId::new(5),
            UserId::new(6),
            &[],
            &everyone_admin,
            g
        ));
    }

    /// 断る文言（サーバーの外・管理者でない）。
    #[test]
    fn refusals_match_python() {
        assert_eq!(
            refusal_for_admin_only(Standing::OutsideGuild),
            Some("ギルド内でのみ使えるぞ。")
        );
        assert_eq!(
            refusal_for_admin_only(Standing::Member),
            Some("管理者のみが余のコマンドを扱えるのだ。貴様には権限がない。")
        );
        assert_eq!(refusal_for_admin_only(Standing::Admin), None);
    }
}
