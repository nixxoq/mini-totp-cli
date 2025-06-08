pub mod totp;

use hmac::Hmac;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;
