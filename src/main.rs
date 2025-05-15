use axum::{
    extract::ConnectInfo,
    extract::State,
    response::Html,
    routing::{get, post},
    Form, Router,
};
use sailfish::TemplateSimple;
use serde::Deserialize;
use sqlx::{
    postgres::{PgPool, PgPoolOptions},
    query,
};
use std::{env, net::SocketAddr};
use tokio::net::TcpListener;
use tower_http::services::ServeDir;

static CSS_FILE: &str = "static/css/hello.css";

#[derive(Clone)]
struct SiteState {
    pool: PgPool,
}

#[derive(TemplateSimple)]
#[template(path = "../templates/hello.stpl")]
struct HelloTemplate {
    css: &'static str,
    addr: String,
}

#[derive(TemplateSimple)]
#[template(path = "../templates/login.stpl")]
struct LoginTemplate {
    css: &'static str,
}

#[derive(TemplateSimple)]
#[template(path = "../templates/login_success.stpl")]
struct LoginSuccessTemplate {
    css: &'static str,
    username: String,
    msg: String,
}

#[derive(Deserialize)]
struct Login {
    username: String,
    password: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(addr).await?;

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL unset!");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    let state = SiteState { pool: pool };

    let site = Router::new()
        .route("/", get(index))
        .route("/login", get(login))
        .route("/login", post(verify_login))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state);

    axum::serve(
        listener,
        site.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn index(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> Html<String> {
    let ctx = HelloTemplate {
        css: CSS_FILE,
        addr: addr.to_string(),
    };

    Html(ctx.render_once().unwrap())
}

async fn login() -> Html<String> {
    let ctx = LoginTemplate { css: CSS_FILE };

    Html(ctx.render_once().unwrap())
}

async fn verify_login(State(state): State<SiteState>, Form(login): Form<Login>) -> Html<String> {
    let result = query!(
        r#"SELECT * FROM Users
        WHERE Username = $1 AND Password = $2"#,
        login.username,
        login.password
    )
    .fetch_all(&state.pool)
    .await
    .expect("Query failed!");

    let mut msg = String::from("Login Failed!");

    if !result.is_empty() {
        msg = String::from("Login Success!");
    };

    let ctx = LoginSuccessTemplate {
        css: CSS_FILE,
        username: login.username,
        msg: msg,
    };

    Html(ctx.render_once().unwrap())
}
