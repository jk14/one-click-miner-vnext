# One-Click Miner with One-Click Submarine Swap

This is an **EXPERIMENTAL**, unprecedented software! (i.e. don't put in what you can't afford to lose!)

This One-Click Miner version is based on upstream: [https://github.com/vertcoin-project/one-click-miner-vnext](https://github.com/vertcoin-project/one-click-miner-vnext)

It allows you to **Submarine Swap** ([more info here](https://blockonomi.com/submarine-swaps/)) your Vertcoins into Lightning Network Bitcoins with a minimal effort.

This software is available for Windows and Linux.

## HOWTO (Read This Carefully!)

### Prerequisites

Download proper .zip archive from [Releases](https://github.com/jk14/one-click-miner-vnext/releases/latest) and unpack it.

Recommended Lightning Network wallet is: [LN Phoenix Wallet](https://phoenix.acinq.co/) from ACINQ (["wen iOS"](https://medium.com/@ACINQ/when-ios-cdf798d5f8ef)).

At current exchange rate - you should have ~10 VTC in OCM to start from scratch (send it to your OCM wallet address if necessary).

If you have plenty of inputs in OCM wallet (like in this example: [VrSwsBBq6TgsAyy8YQdes4we49o6KyiqFU](https://insight.vertcoin.org/insight-vtc-api/addr/VrSwsBBq6TgsAyy8YQdes4we49o6KyiqFU/utxo)) - you may see notification to aggregate it first. In such case - paste your own OCM address in the `Receiver Address` field, enter your password and press `Send`. After [next Vertcoin block](http://insight.vertcoin.org/) - click on `Reload` icon. You can go ahead once you see it back in the `Spendable Balance`.

### Start

Allow OCM in Antivirus/Windows Defender and run ([YT Howto](https://youtu.be/V2uqtXBeKgM?t=129)). Please remember: you can always review the OCM code and build it by yourself ([Building](https://github.com/jk14/one-click-miner-vnext#building)).

### Submarine Swap

If you see the spinning Vertcoin/Bitcoin logo in the `Send coins` tab - type at least **10000** in the `Receiver Address` field (multipurpose now) and click on the `Password` field. **10000 sat** is the minimum amount required for fresh, non-active yet Phoenix Wallet. There is also **1000 sat** fee for on-the-fly channel creation ([more info here](https://phoenix.acinq.co/faq#what-are-the-fees)). If you have some LN wallet working already and you want to unlock the initial payment level - visit our [#one-click-miner-help](https://discord.gg/vertcoin) Discord channel.

In your Phoenix Wallet press `Receive` and `Use LNURL link`. Scan the QR code from OCM and press `Redeem`.

Now enter your OCM wallet password in the highlighted password field and press `Send` only once, then **wait** (even several seconds). In the response message - you can check your submarine swap transaction. After a single confirmation (averages 2.5 minutes) you should see the new payment in your LN Wallet. However, if it has failed for any reason, **funds are SAFU!** A great testing feature of LN network is a contract will expire and six hours later you should see the refund transaction sent automatically to your OCM native SegWit address (if none of these are present after six hours - backup your `refund.txt/refund.old` files and report it here: [#one-click-miner-help](https://discord.gg/vertcoin)).

In case of refund you will need your private key: go to `Send coins` tab, leave empty `Receiver Address`, type your password and press `Send`. Scan the QR code which is the WIF private key (you can use here Sweep function in Coinomi wallet)

Due to refunding procedure - the next swap can be executed after six hours. From this moment minimum swap is 100 sat, maximum is 100,000 sat. There is 1,000 sat fee for on-the-fly channel creation, so check the `RECEIVE` field in the Phoenix `Settings/Channels List` menu. A new channel will be created if your next swap is too close to this value.

Right after submarine swap you will see a zero amount in the `Spendable Balance`. After next Vertcoin block click on `Reload` icon to update it.

Reference level for exchange rate is taken from [Bittrex](https://global.bittrex.com/Market/Index?MarketName=BTC-VTC) API, from the field: `Last` and 1% fee is applied, due to non-zero operational costs (mainly: on-chain fees of funding Lightning Network channels; in this early phase liquidity is provided by me)

Submarine swap instance is based on open source project: [https://github.com/BoltzExchange](https://github.com/BoltzExchange). You can try some other swap options here: [Boltz Exchange](https://boltz.exchange/)

Want to follow along with us? Visit our Discord & support us on Twitter: [https://twitter.com/Vertcoin/status/1369118412883034112](https://twitter.com/Vertcoin/status/1369118412883034112)

If this unique feature is in your opinion groundbreaking enough - just spread the word! If you want to donate further development - please donate like 10 VTC to your friends instead. Install them Phoenix Wallet & Vertcoin One-Click Miner and show how Cool&Easy is to use it! ;)

## FAQ

### Which GPUs are supported?

Please refer to this list of [supported hardware.](https://github.com/CryptoGraphics/VerthashMiner#supported-hardware)

### I have an error message that reads 'Failure to configure'

You may need to add an exclusion to your antivirus / Windows Defender.

### My GPU is supported but an error messages reads 'no compatible GPUs'

Update your GPU drivers to the latest version.


## Building

The GUI of this MVP is based on [Wails](https://wails.app) and [Go](https://golang.org/). It also uses [QRCanvas](https://github.com/gera2ld/qrcanvas).

Install the Wails [prerequisites](https://wails.app/home.html#prerequisites) for your platform, and then run:

```bash
go get github.com/wailsapp/wails/cmd/wails
```

Then clone this repository, and inside its main folder, execute:

```bash
npm install --save qrcanvas-vue
wails build
```

## Donations

If you want to support the further development of the One Click Miner, feel free to donate Vertcoin to [Vmnbtn5nnNbs1otuYa2LGBtEyFuarFY1f8](https://insight.vertcoin.org/address/Vmnbtn5nnNbs1otuYa2LGBtEyFuarFY1f8).
