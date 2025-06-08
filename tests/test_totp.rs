use std::time::{Duration, SystemTime};

use mini_totp_cli::totp::Totp;

#[test]
fn test_generation() {
    let totp = Totp::new("secret".to_owned(), "JBSWY3DPK5XXE3DE".to_owned(), 6, 30);

    let june_01_2022 = SystemTime::UNIX_EPOCH + Duration::new(1_654_084_800, 0);
    let res = totp.generate(Some(june_01_2022));

    println!("{:?}", res);

    assert!(res.is_ok());
    assert_eq!(res.unwrap(), "435428");
}
