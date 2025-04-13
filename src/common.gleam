import gleam/bit_array

@external(erlang, "pot_base32", "encode")
pub fn base32_encode(data: BitArray) -> BitArray

pub type DigestMethod {
  SHA
  SHA256
  SHA384
  SHA512
}

pub type Token {
  StringToken(String)
  BitArrayToken(BitArray)
}

pub fn parse_token(token: Token) {
  case token {
    BitArrayToken(ba) -> ba
    StringToken(s) -> s |> bit_array.from_string
  }
}

pub fn parse_secret(secret: Secret) {
  case secret {
    BitArraySecret(ba) -> base32_encode(ba)
    StringSecret(s) -> s |> bit_array.from_string |> base32_encode
  }
}

pub type Secret {
  StringSecret(String)
  BitArraySecret(BitArray)
}
