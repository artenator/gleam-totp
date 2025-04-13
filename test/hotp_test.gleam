import common
import gleam/time/timestamp
import gleeunit
import gleeunit/should
import hotp

pub fn main() {
  gleeunit.main()
}

pub fn hotp_test() {
  let otp = echo hotp.hotp(common.StringSecret("hello"), 3)
  let valid =
    echo hotp.valid_hotp(
      common.StringToken("191133"),
      common.StringSecret("hello"),
    )
  echo hotp.valid_hotp_with_options(
    common.StringToken("597946"),
    common.StringSecret("hello"),
    hotp.default_options() |> hotp.set_last(2) |> hotp.set_return_interval(True),
  )
}

pub fn hotp_options_test() {
  echo hotp.hotp_with_options(
    common.StringSecret("hello"),
    3,
    hotp.default_options()
      |> hotp.set_digest_method(common.SHA512),
  )
  // 610935
}
