#!/usr/bin/env ruby
# frozen_string_literal: true

# eth.rb — Ethereum blockchain queries via Alchemy JSON-RPC
#
# Usage:
#   ./eth.rb                               — show latest block number
#   ./eth.rb <address>                     — show ETH balance of <address>
#   ./eth.rb --price                       — show current ETH/USD price
#   ./eth.rb --version or -v               — show version
#   ./eth.rb send <key> <to> <amount>      — send ETH (amount in ETH)
#   ./eth.rb send <key> <to> \$<amount>     — send ETH (amount in USD, converted at current price)
#   ./eth.rb --help                        — show this usage info

require "net/http"
require "json"
require "uri"
require "securerandom"
require "ecdsa"
require "digest/keccak"

ALCHEMY_URL     = "https://eth-mainnet.g.alchemy.com/v2/alch_PhpVkmsabZhYV69otj1rF"
COINGECKO_URL   = "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd"
CHAIN_ID        = 1  # Ethereum mainnet
VERSION         = "0.1.4"

# ── JSON-RPC ────────────────────────────────────────────────────────────────

def rpc_call(method, params = [])
  uri  = URI(ALCHEMY_URL)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true

  payload = {
    jsonrpc: "2.0",
    id:      1,
    method:  method,
    params:  params
  }

  request          = Net::HTTP::Post.new(uri.path)
  request.body    = JSON.generate(payload)
  request["Content-Type"] = "application/json"

  response = http.request(request)

  unless response.code.to_i == 200
    puts "HTTP Error: #{response.code} — #{response.message}"
    exit 1
  end

  result = JSON.parse(response.body)

  if (error = result["error"])
    puts "JSON-RPC Error (#{error['code']}): #{error['message']}"
    exit 1
  end

  result["result"]
end

# ── RLP Encoding ────────────────────────────────────────────────────────────

def rlp_encode(item)
  case item
  when Integer
    rlp_encode_integer(item)
  when String
    rlp_encode_bytes(item)
  when Array
    rlp_encode_list(item)
  else
    raise "Unsupported RLP type: #{item.class}"
  end
end

def rlp_encode_integer(int)
  if int.zero?
    rlp_encode_bytes("")
  else
    rlp_encode_bytes(to_big_endian(int))
  end
end

def rlp_encode_bytes(bytes)
  len = bytes.bytesize
  if len == 1 && bytes.ord < 0x80
    bytes
  elsif len <= 55
    (0x80 + len).chr + bytes
  else
    len_bytes = to_big_endian(len)
    (0xb7 + len_bytes.bytesize).chr + len_bytes + bytes
  end
end

def rlp_encode_list(items)
  encoded = items.map { |i| rlp_encode(i) }.join
  len = encoded.bytesize
  if len <= 55
    (0xc0 + len).chr + encoded
  else
    len_bytes = to_big_endian(len)
    (0xf7 + len_bytes.bytesize).chr + len_bytes + encoded
  end
end

def to_big_endian(int)
  return "" if int.zero?
  hex = int.to_s(16)
  hex = "0#{hex}" if hex.bytesize.odd?
  [hex].pack("H*")
end

# ── Crypto helpers ──────────────────────────────────────────────────────────

def keccak256(data)
  Digest::Keccak.digest(data, 256)
end

GROUP = ECDSA::Group::Secp256k1

# Derive address (0x-prefixed hex) from a raw 20-byte address string
def hex_address(raw)
  "0x#{raw.unpack1('H*')}"
end

# Derive the 20-byte address from a private key hex string (with or without 0x)
def private_key_to_address(priv_hex)
  priv_int  = normalize_hex(priv_hex).to_i(16)
  pub_point = GROUP.generator.multiply_by_scalar(priv_int)

  # Uncompressed public key: 04 || x_bytes || y_bytes
  x_bytes = to_big_endian(pub_point.x)
  y_bytes = to_big_endian(pub_point.y)

  # Pad x and y to 32 bytes each
  pad32 = ->(b) { b.bytesize >= 32 ? b : "\x00" * (32 - b.bytesize) + b }

  pub_raw = pad32.call(x_bytes) + pad32.call(y_bytes)

  # Address = last 20 bytes of keccak256(pubkey)
  hash = keccak256(pub_raw)
  hash.byteslice(12, 20)
end

def normalize_hex(str)
  hex = str.start_with?("0x") || str.start_with?("0X") ? str[2..] : str
  hex = "0#{hex}" if hex.bytesize.odd?
  hex
end

# ── Transaction signing ─────────────────────────────────────────────────────

def build_and_sign_tx(private_key_hex, to_address, amount_wei)
  priv_int = normalize_hex(private_key_hex).to_i(16)
  sender_pub_point = GROUP.generator.multiply_by_scalar(priv_int)

  # Derive sender address to match back later for recovery ID
  sender_raw = private_key_to_address(private_key_hex)

  # Get nonce
  sender_hex = "0x#{sender_raw.unpack1('H*')}"
  nonce_hex  = rpc_call("eth_getTransactionCount", [sender_hex, "pending"])
  nonce      = nonce_hex.to_i(16)

  # Get gas price
  gas_price_hex = rpc_call("eth_gasPrice")
  gas_price     = gas_price_hex.to_i(16)

  gas_limit = 21_000      # standard for a simple ETH transfer
  value     = amount_wei
  to_bytes  = [normalize_hex(to_address)].pack("H*")
  data      = ""

  amount_eth = value / 1_000_000_000_000_000_000.0
  puts "Sender:  #{sender_hex}"
  puts "To:      #{to_address}"
  puts "Amount:  #{format('%.18f', amount_eth)} ETH (#{value} wei)"
  puts "Nonce:   #{nonce}"
  puts "Gas:     #{gas_limit}"
  puts "GasPrice: #{gas_price} wei"
  puts ""

  # EIP-155 signing payload: rlp([nonce, gp, gl, to, value, data, chain_id, 0, 0])
  signing_list = [nonce, gas_price, gas_limit, to_bytes, value, data, CHAIN_ID, 0, 0]
  signing_encoded = rlp_encode(signing_list)
  digest = keccak256(signing_encoded)

  # Generate random k (temporary key)
  temp_key = SecureRandom.random_number(GROUP.order - 1) + 1

  sig = ECDSA.sign(GROUP, priv_int, digest, temp_key)
  raise "Signing produced s=0, try again" if sig.nil?

  # Normalize s to low-s (required by Ethereum)
  s = sig.s
  if s > GROUP.order / 2
    s = GROUP.order - s
  end

  low_sig = ECDSA::Signature.new(sig.r, s)

  # Determine recovery ID by trying each possible recovered public key
  rec_id = nil
  ECDSA.recover_public_key(GROUP, digest, low_sig).each_with_index do |point, i|
    # Reconstruct raw public key from point
    xb = to_big_endian(point.x)
    yb = to_big_endian(point.y)
    pad32 = ->(b) { b.bytesize >= 32 ? b : "\x00" * (32 - b.bytesize) + b }
    raw_pub = pad32.call(xb) + pad32.call(yb)
    addr = keccak256(raw_pub).byteslice(12, 20)
    if addr == sender_raw
      rec_id = i
      break
    end
  end

  raise "Could not determine recovery ID" if rec_id.nil?

  v = 35 + CHAIN_ID * 2 + rec_id

  # Signed transaction: rlp([nonce, gp, gl, to, value, data, v, r, s])
  # r and s are encoded as integers (not padded byte strings) per Ethereum spec
  tx_list = [nonce, gas_price, gas_limit, to_bytes, value, data, v, low_sig.r, s]
  rlp_encode(tx_list)
end

# ── Send command ────────────────────────────────────────────────────────────

def cmd_send(args)
  # p args
  if args.length < 3
    puts "Usage: ./eth.rb send <private_key_hex> <to_address> <amount>"
    puts "  amount: number (ETH) or $number (USD, converted to ETH at current price)"
    exit 1
  end

  private_key = args[0]
  to_address  = args[1]
  raw_amount  = args[2]
  exit if raw_amount.to_f == 0 && raw_amount[1..].to_f == 0

  # Parse amount: $X → USD, otherwise treat as ETH
  if raw_amount.start_with?("$")
    usd_amount = raw_amount[1..].to_f
    price = fetch_eth_price
    eth_amount = usd_amount / price
    puts "Converting $#{format('%.2f', usd_amount)} → #{format('%.8f', eth_amount)} ETH (price: $#{format('%.2f', price)})"
  else
    eth_amount = raw_amount.to_f
  end

  amount_wei = (eth_amount * 1_000_000_000_000_000_000).to_i
  # puts "Wei: #{amount_wei}"

  puts "Building and signing transaction..."
  signed_tx = build_and_sign_tx(private_key, to_address, amount_wei)
  tx_hex = "0x#{signed_tx.unpack1('H*')}"

  puts "Broadcasting..."
  tx_hash = rpc_call("eth_sendRawTransaction", [tx_hex])
  puts "Transaction sent! TxHash: #{tx_hash}"
end

# ── Display commands ────────────────────────────────────────────────────────

def show_block_number
  hex_block = rpc_call("eth_blockNumber")
  block_num = hex_block.to_i(16)
  puts "Latest Ethereum block: ##{block_num}"
  puts "Hex: #{hex_block}"
end

def show_balance(address)
  hex_wei = rpc_call("eth_getBalance", [address, "latest"])
  wei     = hex_wei.to_i(16)
  eth     = wei / 1_000_000_000_000_000_000.0   # wei → ETH (18 decimals)
  eth_fmt = format("%.18f", eth)

  # Fetch ETH/USD price and compute USD value
  price = fetch_eth_price
  usd   = eth * price
  usd_fmt = format("%.2f", usd)

  puts "Address: #{address}"
  puts "Balance: #{eth_fmt} ETH (#{wei} wei)"
  puts "Value:   $#{usd_fmt} USD @ $#{format("%.2f", price)}/ETH"
end

def fetch_eth_price
  uri  = URI(COINGECKO_URL)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true

  request = Net::HTTP::Get.new(uri)
  request["Accept"] = "application/json"

  response = http.request(request)

  unless response.code.to_i == 200
    puts "HTTP Error: #{response.code} — #{response.message}"
    exit 1
  end

  data = JSON.parse(response.body)

  unless (price = data.dig("ethereum", "usd"))
    puts "Could not fetch ETH price"
    exit 1
  end

  price
end

def show_price
  price = fetch_eth_price
  puts "ETH/USD: $#{format("%.2f", price)}"
end

def show_version
  puts "eth.rb v#{VERSION}"
end

def print_usage
  puts File.read(__FILE__)[/^#\sUsage:.*?(?=\n\n)/m]
end

# ── CLI dispatch ────────────────────────────────────────────────────────────

def run_cli(args)
  if args.empty?
    show_block_number
  elsif args[0] == "--price"
    show_price
  elsif args[0] == "--version" || args[0] == "-v"
    show_version
  elsif args[0] == "--help" || args[0] == "-h"
    print_usage
  elsif args[0] == "send"
    cmd_send(args[1..])
  else
    show_balance(args[0])
  end
end

# p ARGV
run_cli(ARGV) if __FILE__ == $0
