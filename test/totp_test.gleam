import gleam/time/timestamp
import gleeunit
import gleeunit/should
import totp

pub fn main() {
  gleeunit.main()
}

pub fn totp_test() {
  let otp = echo totp.totp(totp.StringSecret("hello"))
  let valid =
    echo totp.valid_totp(totp.StringToken("191133"), totp.StringSecret("hello"))
}

pub fn totp_options_test() {
  echo totp.totp_with_options(
    totp.StringSecret("hello"),
    totp.default_options()
      |> totp.set_digest_method(totp.SHA512)
      |> totp.set_timestamp(timestamp.from_unix_seconds(1_743_965_504)),
  )
  // 610935
  echo timestamp.to_unix_seconds_and_nanoseconds
}
