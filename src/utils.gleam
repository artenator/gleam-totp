import gleam/float
import gleam/int
import gleam/time/timestamp.{type Timestamp}

pub fn to_erlang_timestamp(timestamp: Timestamp) {
  let #(secs, nanos) = timestamp.to_unix_seconds_and_nanoseconds(timestamp)
  let mega_seconds = secs / 1_000_000
  let micro_seconds = int.to_float(nanos) *. 0.001 |> float.truncate

  #(mega_seconds, secs % 1_000_000, micro_seconds)
}
