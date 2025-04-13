import common.{
  type DigestMethod, type Secret, type Token, SHA, SHA256, SHA384, SHA512,
  parse_secret, parse_token,
}
import gleam/bit_array
import gleam/erlang.{type Crash, rescue}
import gleam/erlang/atom.{type Atom}
import gleam/io
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/time/timestamp.{type Timestamp}
import utils

pub opaque type TotpError {
  ErlangCrash(Crash)
  StringError
}

pub opaque type TotpOption {
  Addwindow(window: Int)
  DigestMethod(method: Atom)
  IntervalLength(length: Int)
  Timestamp(timestamp: #(Int, Int, Int))
  TokenLength(length: Int)
  Window(window: Int)
}

pub opaque type TotpOptions {
  TotpOptions(
    addwindow: Option(Int),
    digest_method: Option(String),
    interval_length: Option(Int),
    timestamp: Option(Timestamp),
    token_length: Option(Int),
    window: Option(Int),
  )
}

pub fn default_options() {
  TotpOptions(
    addwindow: None,
    digest_method: None,
    interval_length: None,
    timestamp: None,
    token_length: None,
    window: None,
  )
}

pub fn set_add_window(from options: TotpOptions, to window: Int) {
  TotpOptions(..options, addwindow: Some(window))
}

pub fn set_digest_method(
  from options: TotpOptions,
  to digest_method: DigestMethod,
) {
  TotpOptions(
    ..options,
    digest_method: Some(case digest_method {
      SHA -> "sha"
      SHA256 -> "sha256"
      SHA384 -> "sha384"
      SHA512 -> "sha512"
    }),
  )
}

pub fn set_interval_length(from options: TotpOptions, to interval_length: Int) {
  TotpOptions(..options, interval_length: Some(interval_length))
}

pub fn set_timestamp(from options: TotpOptions, to timestamp: Timestamp) {
  TotpOptions(..options, timestamp: Some(timestamp))
}

pub fn set_token_length(from options: TotpOptions, to token_length: Int) {
  TotpOptions(..options, token_length: Some(token_length))
}

pub fn set_window(from options: TotpOptions, to window: Int) {
  TotpOptions(..options, window: Some(window))
}

fn create_digest_method(from s: String) -> TotpOption {
  s |> atom.create_from_string |> DigestMethod
}

fn to_pot_totp_options(from options: TotpOptions) {
  [
    options.addwindow |> option.map(Addwindow),
    options.digest_method |> option.map(create_digest_method),
    options.interval_length |> option.map(IntervalLength),
    options.timestamp
      |> option.map(fn(ts) { ts |> utils.to_erlang_timestamp |> Timestamp }),
    options.token_length |> option.map(TokenLength),
    options.window |> option.map(Window),
  ]
  |> option.values
}

fn to_pot_valid_totp_options(from options: TotpOptions) {
  [
    options.addwindow |> option.map(Addwindow),
    options.digest_method |> option.map(create_digest_method),
    options.interval_length |> option.map(IntervalLength),
    options.timestamp
      |> option.map(fn(ts) { ts |> utils.to_erlang_timestamp |> Timestamp }),
    options.token_length |> option.map(TokenLength),
  ]
  |> option.values
}

@external(erlang, "pot", "totp")
fn pot_totp(secret: BitArray) -> BitArray

@external(erlang, "pot", "totp")
fn pot_totp_with_options(
  secret: BitArray,
  options: List(TotpOption),
) -> BitArray

@external(erlang, "pot", "valid_totp")
fn pot_valid_totp(token: BitArray, secret: BitArray) -> Bool

@external(erlang, "pot", "valid_totp")
fn pot_valid_totp_with_options(
  token: BitArray,
  secret: BitArray,
  options: List(TotpOption),
) -> Bool

pub fn valid_totp(token: Token, secret: Secret) -> Result(Bool, TotpError) {
  let token_parsed = parse_token(token)
  let secret_parsed = parse_secret(secret)
  rescue(fn() { token_parsed |> pot_valid_totp(secret_parsed) })
  |> result.map_error(ErlangCrash)
}

pub fn valid_totp_with_options(
  token: Token,
  secret: Secret,
  options: TotpOptions,
) -> Result(Bool, TotpError) {
  let token_parsed = parse_token(token)
  let secret_parsed = parse_secret(secret)
  let valid_totp_options = to_pot_valid_totp_options(options)
  rescue(fn() {
    token_parsed
    |> pot_valid_totp_with_options(secret_parsed, valid_totp_options)
  })
  |> result.map_error(ErlangCrash)
}

pub fn totp(secret: Secret) -> Result(String, TotpError) {
  let secret_b32 = parse_secret(secret)
  rescue(fn() {
    secret_b32
    |> pot_totp
    |> bit_array.to_string
  })
  |> result.map_error(ErlangCrash)
  |> result.try(result.map_error(_, fn(_) { StringError }))
}

pub fn totp_with_options(
  secret: Secret,
  options: TotpOptions,
) -> Result(String, TotpError) {
  let secret_b32 = parse_secret(secret)
  let totp_options = to_pot_totp_options(options)
  rescue(fn() {
    secret_b32
    |> pot_totp_with_options(totp_options)
    |> bit_array.to_string
  })
  |> result.map_error(ErlangCrash)
  |> result.try(result.map_error(_, fn(_) { StringError }))
}
