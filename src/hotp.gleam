import common.{
  type DigestMethod, type Secret, type Token, SHA, SHA256, SHA384, SHA512,
  parse_secret, parse_token,
}
import gleam/bit_array
import gleam/dynamic.{classify}
import gleam/dynamic/decode
import gleam/erlang.{type Crash, rescue}
import gleam/erlang/atom.{type Atom}
import gleam/option.{type Option, None, Some}
import gleam/result

pub opaque type HotpError {
  ErlangCrash(Crash)
  StringError
  ClassifyError
}

pub opaque type HotpOption {
  DigestMethod(method: Atom)
  Last(interval: Int)
  ReturnInterval(return: Bool)
  TokenLength(length: Int)
  Trials(range: Int)
}

pub opaque type HotpOptions {
  HotpOptions(
    digest_method: Option(String),
    last: Option(Int),
    return_interval: Option(Bool),
    token_length: Option(Int),
    trials: Option(Int),
  )
}

@external(erlang, "pot", "hotp")
fn pot_hotp(secret: BitArray, interval: Int) -> BitArray

@external(erlang, "pot", "hotp")
fn pot_hotp_with_options(
  secret: BitArray,
  interval: Int,
  options: List(HotpOption),
) -> BitArray

@external(erlang, "pot", "valid_hotp")
fn pot_valid_hotp(token: BitArray, secret: BitArray) -> Bool

@external(erlang, "pot", "valid_hotp")
fn pot_valid_hotp_with_options(
  token: BitArray,
  secret: BitArray,
  options: List(HotpOption),
) -> dynamic

pub fn default_options() {
  HotpOptions(
    digest_method: None,
    last: None,
    return_interval: None,
    token_length: None,
    trials: None,
  )
}

pub fn set_digest_method(
  from options: HotpOptions,
  to digest_method: DigestMethod,
) {
  HotpOptions(
    ..options,
    digest_method: Some(case digest_method {
      SHA -> "sha"
      SHA256 -> "sha256"
      SHA384 -> "sha384"
      SHA512 -> "sha512"
    }),
  )
}

pub fn set_last(from options: HotpOptions, to last: Int) {
  HotpOptions(..options, last: Some(last))
}

pub fn set_return_interval(from options: HotpOptions, to return_interval: Bool) {
  HotpOptions(..options, return_interval: Some(return_interval))
}

pub fn set_token_length(from options: HotpOptions, to token_length: Int) {
  HotpOptions(..options, token_length: Some(token_length))
}

pub fn set_trials(from options: HotpOptions, to trials: Int) {
  HotpOptions(..options, trials: Some(trials))
}

fn create_digest_method(from s: String) -> HotpOption {
  s |> atom.create_from_string |> DigestMethod
}

fn to_pot_hotp_options(from options: HotpOptions) {
  [
    options.digest_method |> option.map(create_digest_method),
    options.token_length |> option.map(TokenLength),
  ]
  |> option.values
}

fn to_pot_valid_hotp_options(from options: HotpOptions) {
  [
    options.digest_method |> option.map(create_digest_method),
    options.last |> option.map(Last),
    options.return_interval |> option.map(ReturnInterval),
    options.token_length |> option.map(TokenLength),
    options.trials |> option.map(Trials),
  ]
  |> option.values
}

pub fn valid_hotp(token: Token, secret: Secret) -> Result(Bool, HotpError) {
  let token_parsed = parse_token(token)
  let secret_parsed = parse_secret(secret)
  rescue(fn() { token_parsed |> pot_valid_hotp(secret_parsed) })
  |> result.map_error(ErlangCrash)
}

pub fn valid_hotp_with_options(
  token: Token,
  secret: Secret,
  options: HotpOptions,
) -> Result(#(Option(Bool), Option(Int)), HotpError) {
  let token_parsed = parse_token(token)
  let secret_parsed = parse_secret(secret)
  let valid_hotp_options = echo to_pot_valid_hotp_options(options)
  rescue(fn() {
    token_parsed
    |> pot_valid_hotp_with_options(secret_parsed, valid_hotp_options)
  })
  |> result.map_error(ErlangCrash)
  |> result.try(fn(r) {
    case classify(r) {
      "Tuple of 2 elements" ->
        #(
          r
            |> decode.run(decode.at([0], decode.bool))
            |> option.from_result,
          r
            |> decode.run(decode.at([1], decode.int))
            |> option.from_result,
        )
        |> Ok
      "Bool" ->
        #(
          r
            |> decode.run(decode.bool)
            |> option.from_result,
          None,
        )
        |> Ok
      _ -> Error(ClassifyError)
    }
  })
}

pub fn hotp(secret: Secret, interval: Int) -> Result(String, HotpError) {
  let secret_b32 = parse_secret(secret)
  rescue(fn() {
    secret_b32
    |> pot_hotp(interval)
    |> bit_array.to_string
  })
  |> result.map_error(ErlangCrash)
  |> result.try(result.map_error(_, fn(_) { StringError }))
}

pub fn hotp_with_options(
  secret: Secret,
  interval: Int,
  options: HotpOptions,
) -> Result(String, HotpError) {
  let secret_b32 = parse_secret(secret)
  let hotp_options = to_pot_hotp_options(options)
  rescue(fn() {
    secret_b32
    |> pot_hotp_with_options(interval, hotp_options)
    |> bit_array.to_string
  })
  |> result.map_error(ErlangCrash)
  |> result.try(result.map_error(_, fn(_) { StringError }))
}
