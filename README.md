# eth.rb

A lightweight Ethereum CLI in Ruby: balances, prices, key generation, and
transactions via Alchemy JSON-RPC.

## Install

### Homebrew

```sh
brew tap khalidjshaikh/tap
brew install khalidjshaikh/tap/eth
```

The formula installs the `eth.rb` executable from the published
[eth-rb](https://rubygems.org/gems/eth-rb) gem, fully self-contained in its own
gem directory.

### RubyGems

```sh
gem install eth-rb
```

## Usage

```
eth.rb                               — show latest block number
eth.rb <address>                     — show ETH balance of <address>
eth.rb <private_key>                 — derive public key + address, show balance
eth.rb --price                       — show current ETH/USD price
eth.rb --genkey or -g                — generate a new private key + address
eth.rb --pubkey <key>                — derive public key + address from <key>
eth.rb --version or -v               — show version
eth.rb --send <key> <to> <amount>    — send ETH (amount in ETH)
eth.rb --send <key> <to> \$<amount>  — send ETH (amount in USD, converted at current price)
eth.rb --help                        — show usage info
```

## Development

```sh
bundle install
ruby exe/eth.rb --version
gem build eth-rb.gemspec
```

## Homebrew formula

The formula lives in the [`homebrew-tap`](https://github.com/khalidjshaikh/homebrew-tap)
repository at `Formula/eth.rb`. To bump it for a new release, update `version`,
the gem `url`, and its `sha256` (from `shasum -a 256 eth-rb-<version>.gem`).

## License

MIT
