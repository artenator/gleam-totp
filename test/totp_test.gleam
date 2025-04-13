import common
import gleam/time/timestamp
import gleeunit
import gleeunit/should
import totp

pub fn main() {
  gleeunit.main()
}

pub fn totp_test() {
  let otp = echo totp.totp(common.StringSecret("hello"))
  let valid =
    echo totp.valid_totp(
      common.StringToken("191133"),
      common.StringSecret("hello"),
    )
}

pub fn totp_options_test() {
  echo totp.totp_with_options(
    common.StringSecret("hello"),
    totp.default_options()
      |> totp.set_digest_method(common.SHA512)
      |> totp.set_timestamp(timestamp.from_unix_seconds(1_743_965_504)),
  )
  // 610935
}
