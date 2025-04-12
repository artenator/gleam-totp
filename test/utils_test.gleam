import gleam/time/timestamp
import gleeunit
import utils

pub fn main() {
  gleeunit.main()
}

pub fn to_erlang_timestamp_test() {
  echo utils.to_erlang_timestamp(timestamp.system_time())
}
