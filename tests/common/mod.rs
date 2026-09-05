pub fn assert_isolated_database() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is required");
    let test_url = std::env::var("ERI_TEST_DATABASE_URL")
        .expect("ERI_TEST_DATABASE_URL is required for database tests");
    assert!(
        database_url == test_url,
        "database tests require the isolated test URL"
    );
    let parsed = url::Url::parse(&test_url).expect("ERI_TEST_DATABASE_URL must be a URL");
    assert_eq!(
        parsed.path(),
        "/eri_inf008_test",
        "database tests require the task-owned eri_inf008_test database"
    );
}
