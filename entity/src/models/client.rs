//! `SeaORM` Entity, @generated by sea-orm-codegen 1.1.0

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "client")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    pub two_factor_enabled_at: Option<DateTimeWithTimeZone>,
    pub max_concurrent_sessions: i32,
    pub session_lifetime: i32,
    pub use_refresh_token: bool,
    pub refresh_token_lifetime: i32,
    pub refresh_token_reuse_limit: i32,
    pub is_account_activation_required: bool,
    pub locked_at: Option<DateTimeWithTimeZone>,
    pub realm_id: Uuid,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::api_user::Entity")]
    ApiUser,
    #[sea_orm(
        belongs_to = "super::realm::Entity",
        from = "Column::RealmId",
        to = "super::realm::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    Realm,
    #[sea_orm(has_many = "super::refresh_token::Entity")]
    RefreshToken,
    #[sea_orm(has_many = "super::resource_group::Entity")]
    ResourceGroup,
    #[sea_orm(has_many = "super::session::Entity")]
    Session,
}

impl Related<super::api_user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiUser.def()
    }
}

impl Related<super::realm::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Realm.def()
    }
}

impl Related<super::refresh_token::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::RefreshToken.def()
    }
}

impl Related<super::resource_group::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ResourceGroup.def()
    }
}

impl Related<super::session::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Session.def()
    }
}
