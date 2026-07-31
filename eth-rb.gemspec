Gem::Specification.new do |spec|
  spec.name          = "eth-rb"
  spec.version       = "0.1.7"
  spec.authors       = ["Khalid Shaikh"]
  spec.email         = ["k@iai.lol"]

  spec.summary       = "Ethereum CLI: balances, prices, key generation, and transactions via Alchemy JSON-RPC"
  spec.description   = "A lightweight CLI tool for generating Ethereum private keys and addresses, querying balances, block numbers, and ETH/USD prices, and sending transactions via Alchemy JSON-RPC."
  spec.homepage      = "https://github.com/kshaikh/eth.rb"
  spec.license       = "MIT"

  spec.required_ruby_version = ">= 2.5.0"

  spec.files         = Dir["lib/**/*.rb"] + Dir["exe/*"]
  spec.bindir        = "exe"
  spec.executables   = ["eth.rb"]

  spec.add_dependency "ecdsa",  "~> 1.2"
  spec.add_dependency "keccak", "~> 1.3"
end
