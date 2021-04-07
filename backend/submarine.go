package backend

import (
	"fmt"
	"net/http"
	"log"
	"io/ioutil"
	"encoding/json"
	"strconv"
	"math"
	"os"
        "path/filepath"
	"bufio"
	"strings"
	"time"
	"encoding/hex"
	"bytes"
	"crypto/sha256"
	"crypto/rand"
	"errors"

	"github.com/vertcoin-project/one-click-miner-vnext/logging"
	"github.com/vertcoin-project/one-click-miner-vnext/util"
	"github.com/vertcoin-project/one-click-miner-vnext/keyfile"
	"github.com/vertcoin-project/one-click-miner-vnext/util/bech32"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcd/txscript"
	"github.com/fiatjaf/go-lnurl"
)

type Bittrex struct {
	Symbol        string `json:"symbol"`
	Lasttraderate string `json:"lastTradeRate"`
	Bidrate       string `json:"bidRate"`
	Askrate       string `json:"askRate"`
}

type CreateSwap struct {
        Type            string `json:"type"`
        PairID          string `json:"pairId"`
        OrderSide       string `json:"orderSide"`
        Invoice         string `json:"invoice"`
        RefundPublicKey string `json:"refundPublicKey"`
}

type CreateResponse struct {
        ID                 string `json:"id"`
        Bip21              string `json:"bip21"`
        Address            string `json:"address"`
        RedeemScript       string `json:"redeemScript"`
        AcceptZeroConf     bool   `json:"acceptZeroConf"`
        ExpectedAmount     int    `json:"expectedAmount"`
        TimeoutBlockHeight int    `json:"timeoutBlockHeight"`
        Error              string `json:"error"`
}

type InvoiceResponse struct {
        Invoice            string `json:"invoice"`
        Amount             int64    `json:"amount"`
}

type UtxoResponse []struct {
	Txid     string `json:"txid"`
	Vout     int    `json:"vout"`
	Satoshis int    `json:"satoshis"`
}

type OutputType int

const (
        SegWit OutputType = iota
        Compatibility
        Legacy
)

type OutputDetails struct {
        LockupTransaction *btcutil.Tx
        Vout              uint32
        OutputType        OutputType

        RedeemScript []byte
        PrivateKey   *btcec.PrivateKey
        // Should be set to an empty array in case of a refund
        Preimage []byte
        TimeoutBlockHeight uint32
}

func GenerateInfo(vtc_bal float64) (int64, string) {
	sat_max, ex_rate, err := BittrexGet(vtc_bal)
	if err != nil {
		logging.Errorf("BittrexGet error: %s", err)
		return 0, ""
	}
	ex_str := fmt.Sprintf("%d", sat_max) + " @ " + fmt.Sprintf("%d", ex_rate)

	return sat_max, ex_str
}

func TryRedeem() (string, error) {
	//if refund.txt exist, read the content; if over 6h - try to redeem and rotate files
	refundtxtPath := filepath.Join(util.DataDirectory(), "refund.txt")
	refundoldPath := filepath.Join(util.DataDirectory(), "refund.old")

	if _, err := os.Stat(refundtxtPath); err == nil {
		f, err := os.Open(refundtxtPath)
		if err != nil { return "", err }

		reader := bufio.NewReader(f)
		var line string
		line, err = reader.ReadString('\n')
		err = f.Close();
		if err != nil { logging.Errorf("Close error: %s", err) }

		redeem_str := strings.Split(line, ";")
		sec_then, err := strconv.ParseInt(redeem_str[0], 10, 64)
		if err != nil { logging.Errorf("Parse error: %s", err) }

		t := time.Now()
		sec_now := t.Unix()

		if (sec_now - sec_then) > 21600 {

			sub_script, err := bech32.SegWitAddressDecode(redeem_str[3])
			if err != nil { return "", nil }

			url := "https://ocm-backend.blkidx.org/utxos/"
			url += hex.EncodeToString(sub_script)
			resp, err := http.Get(url)
			if err != nil {
				logging.Errorf("backend utxo error: %s", err)
				return "", nil
			}
			defer resp.Body.Close()
			bodyBytes, _ := ioutil.ReadAll(resp.Body)

			var utxo_resp UtxoResponse
			json.Unmarshal(bodyBytes, &utxo_resp)

			err = os.Rename(refundtxtPath, refundoldPath)
			if err != nil { log.Fatal(err) }

			if len(utxo_resp) == 1 {
				return redeem_str[8], nil
			} else {
				return "", nil
			}
		}
	}

	return "", nil
}

func BittrexGet(x float64) (int64, int64, error) {
        if x == 0 {
		return 0, 0, nil
	}
        resp, err := http.Get("https://api.bittrex.com/v3/markets/VTC-BTC/ticker")
        if err != nil { return 0, 0, err }

        defer resp.Body.Close()
        bodyBytes, _ := ioutil.ReadAll(resp.Body)

        var bittrexStruct Bittrex
        json.Unmarshal(bodyBytes, &bittrexStruct)

	rate_f, err := strconv.ParseFloat(bittrexStruct.Lasttraderate, 64)
	if err != nil { logging.Errorf("Parse error: %s", err) }

        rate_f *= 0.99
	r_rate_f := math.Floor(rate_f*100000000)

	btc_f := x * r_rate_f
	r_btc_f := math.Floor(btc_f/100)*100

	r_rate := int64(r_rate_f)
	r_sat := int64(r_btc_f)

        return r_sat, r_rate, nil
}

func SubPost(s_invoice string, s_refpubkey string) (string, string, error) {
        create_swap := CreateSwap{"submarine", "VTC/BTC", "sell", s_invoice, s_refpubkey}
        jsonReq, err := json.Marshal(create_swap)

        resp, err := http.Post("http://161.97.127.179:5890/createswap", "application/json", bytes.NewBuffer(jsonReq))
        if err != nil {
                logging.Errorf("Boltz instance error\n")
		return "Error: ", "Boltz instance error", err
	}

        defer resp.Body.Close()
        bodyBytes, _ := ioutil.ReadAll(resp.Body)

        var cs_response CreateResponse
        json.Unmarshal(bodyBytes, &cs_response)

	resp_len := len(cs_response.Error)
        if resp_len > 0 {
                logging.Errorf("Boltz response error: %s\n", cs_response.Error)
		return "Error: ", cs_response.Error, nil
	} else if cs_response.ExpectedAmount == 0 {
                logging.Errorf("Boltz error\n")
		return "Error: ", "Boltz error", nil
        } else {
                // TODO verify if cs_response.Address is the submarine address
                //if address OK
                //
                        //write data to refund.txt
                        refundPath := filepath.Join(util.DataDirectory(), "refund.txt")
                        f, err := os.OpenFile(refundPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
                        if err != nil { logging.Errorf("Open error: %s\n", err) }

                        t := time.Now()
			var tmpstr string
                        tmpstr = fmt.Sprintf("%d", t.Unix())
                        f.WriteString(tmpstr)
                        f.WriteString(";")
                        f.WriteString(cs_response.ID)
                        f.WriteString(";")
                        tmpstr = fmt.Sprintf("%d", cs_response.ExpectedAmount)
                        f.WriteString(tmpstr)
                        f.WriteString(";")
                        f.WriteString(cs_response.Address)
                        f.WriteString(";")
                        f.WriteString(s_invoice)
                        f.WriteString(";")
                        f.WriteString(cs_response.RedeemScript)
                        f.WriteString(";")
                        tmpstr = fmt.Sprintf("%d", cs_response.TimeoutBlockHeight)
                        f.WriteString(tmpstr)
                        f.WriteString(";")

                        err = f.Close();
                        if err != nil { logging.Errorf("Close error: %s\n", err) }

                        tmpstr = fmt.Sprintf("%d", cs_response.ExpectedAmount)
                        logging.Infof("Boltz response: %s %s\n", tmpstr, cs_response.Address)

                        return tmpstr, cs_response.Address, nil
                //else
        }
}

func (m *Backend) PrepareSweepSub(vtc_inv int64, addr string) string {
        logging.Debugf("Preparing submarine sweep")

        txs, err := m.wal.PrepareSweepSubWal(vtc_inv, addr)
        if err != nil {
                logging.Errorf("Error preparing sweep: %v", err)
                return err.Error()
        }

        m.pendingSweep = txs
        val := float64(0)
        for _, tx := range txs {
                val += (float64(tx.TxOut[1].Value) / float64(100000000))
        }

        result := PrepareResult{fmt.Sprintf("%0.8f VTC", val), len(txs)}
        logging.Debugf("Prepared submarine sweep: %v", result)

        return ""
}

func (m *Backend) SendSweepSub(password string) []string {

        txids := make([]string, 0)

        if len(m.pendingSweep) == 0 {
                // Somehow user managed to press send without properly
                // preparing the sweep first
                return []string{"send_failed"}
        }

        for _, s := range m.pendingSweep {
                err := m.wal.SignMyInputs(s, password)
                if err != nil {
                        logging.Errorf("Error signing transaction: %s", err.Error())
                        return []string{"sign_failed"}
                }

                txHash, txHex, err := m.wal.SendSub(s)
                if err != nil {
                        logging.Errorf("Error sending transaction: %s", err.Error())
                        return []string{"send_failed"}
                }
                txids = append(txids, txHash)

                lockupTransactionRaw, err := hex.DecodeString(txHex)
                if err != nil { logging.Errorf("Could not decode lockup transaction\n") }

                lockupTransaction, err := btcutil.NewTxFromBytes(lockupTransactionRaw)
                if err != nil { logging.Errorf("Could not parse lockup transaction\n") }

                outputs := make([]OutputDetails, 1)

                outputs[0].LockupTransaction = lockupTransaction
                outputs[0].Vout = 1
                outputs[0].OutputType = SegWit

                refundPath := filepath.Join(util.DataDirectory(), "refund.txt")

                if _, err := os.Stat(refundPath); err == nil {
                        f2, err := os.Open(refundPath)
                        if err != nil { logging.Errorf("Open error: %s", err) }

                        reader := bufio.NewReader(f2)
                        var line string
                        line, err = reader.ReadString('\n')
                        err = f2.Close();
                        if err != nil { logging.Errorf("Close error: %s", err) }

                        line_split := strings.Split(line, ";")

                        redeem_bytes, err := hex.DecodeString(line_split[5])
                        if err != nil { logging.Errorf("Could not convert redeem script\n") }

                        outputs[0].RedeemScript = redeem_bytes

                        privBytes, err := keyfile.LoadPrivateKey(password)
                        if err != nil { logging.Errorf("LoadPrivateKey failure\n") }
                        priv, pub := btcec.PrivKeyFromBytes(btcec.S256(), privBytes)

                        outputs[0].PrivateKey = priv
                        //outputs[0].Preimage = []byte{}

                        block_no, err := strconv.ParseUint(line_split[6], 10, 64)
                        if err != nil { logging.Errorf("Parse error: %s", err) }
                        outputs[0].TimeoutBlockHeight = uint32(block_no)

                        params := getVertcoinChainParams()
                        chaincfg.Register(&params)

                        pubHash := btcutil.Hash160(pub.SerializeCompressed())

                        witnessAddress, _ := btcutil.NewAddressWitnessPubKeyHash(pubHash, &params)
                        address, _ := btcutil.DecodeAddress(witnessAddress.EncodeAddress(), &params)

                        txref, err := ConstructTransaction(outputs, address, 500)
                        if err != nil { logging.Errorf("ConstructTransaction failure %s\n", err) }

                        var b bytes.Buffer
                        txref.Serialize(&b)
                        encref := hex.EncodeToString(b.Bytes())

                        f, err := os.OpenFile(refundPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
                        if err != nil { logging.Errorf("Open error: %s\n", err) }

                        f.WriteString(txHash)
                        f.WriteString(";")
                        f.WriteString(encref)

                        err = f.Close();
                        if err != nil { logging.Errorf("Close error: %s\n", err) }
                }
        }

        m.pendingSweep = nil

        logging.Debugf("Submarine transaction sent! TXIDs: %v\n", txids)
        m.refreshBalanceChan <- true
        return txids
}

func getVertcoinChainParams() chaincfg.Params {
    var params chaincfg.Params

    params.Bech32HRPSegwit = "vtc"

    return params
}

func ConstructTransaction(outputs []OutputDetails, outputAddress btcutil.Address, satPerVbyte int64) (*wire.MsgTx, error) {
        noFeeTransaction, err := constructTransaction(outputs, outputAddress, 0)

        if err != nil {
                return nil, err
        }

        witnessSize := noFeeTransaction.SerializeSize() - noFeeTransaction.SerializeSizeStripped()
        vByte := int64(noFeeTransaction.SerializeSizeStripped()) + int64(math.Ceil(float64(witnessSize)/4))

        return constructTransaction(outputs, outputAddress, vByte*satPerVbyte)
}

func constructTransaction(outputs []OutputDetails, outputAddress btcutil.Address, fee int64) (*wire.MsgTx, error) {
        transaction := wire.NewMsgTx(wire.TxVersion)

        var inputSum int64

        for _, output := range outputs {
                // Set the highest timeout block height as locktime
                if output.TimeoutBlockHeight > transaction.LockTime {
                        transaction.LockTime = output.TimeoutBlockHeight
                }

                // Calculate the sum of all inputs
                inputSum += output.LockupTransaction.MsgTx().TxOut[output.Vout].Value

                // Add the input to the transaction
                input := wire.NewTxIn(wire.NewOutPoint(output.LockupTransaction.Hash(), output.Vout), nil, nil)
                input.Sequence = 0

                transaction.AddTxIn(input)
        }

        // Add the output
        outputScript, err := txscript.PayToAddrScript(outputAddress)

        if err != nil {
                return nil, err
        }

        transaction.AddTxOut(&wire.TxOut{
                PkScript: outputScript,
                Value:    inputSum - fee,
        })

        // Construct the signature script and witnesses and sign the inputs
        for i, output := range outputs {
                switch output.OutputType {
                case Legacy:
                        // Set the signed signature script for legacy output
                        signature, err := txscript.RawTxInSignature(
                                transaction,
                                i,
                                output.RedeemScript,
                                txscript.SigHashAll,
                                output.PrivateKey,
                        )

                        if err != nil {
                                return nil, err
                        }

                        signatureScriptBuilder := txscript.NewScriptBuilder()
                        signatureScriptBuilder.AddData(signature)
                        signatureScriptBuilder.AddData(output.Preimage)
                        signatureScriptBuilder.AddData(output.RedeemScript)

                        signatureScript, err := signatureScriptBuilder.Script()

                        if err != nil {
                                return nil, err
                        }

                        transaction.TxIn[i].SignatureScript = signatureScript

                case Compatibility:
                        // Set the signature script for compatibility outputs
                        signatureScriptBuilder := txscript.NewScriptBuilder()
                        signatureScriptBuilder.AddData(createNestedP2shScript(output.RedeemScript))

                        signatureScript, err := signatureScriptBuilder.Script()

                        if err != nil {
                                return nil, err
                        }

                        transaction.TxIn[i].SignatureScript = signatureScript
                }

                // Add the signed witness in case the output is not a legacy one
                if output.OutputType != Legacy {
                        signatureHash := txscript.NewTxSigHashes(transaction)
                        signature, err := txscript.RawTxInWitnessSignature(
                                transaction,
                                signatureHash,
                                i,
                                output.LockupTransaction.MsgTx().TxOut[output.Vout].Value,
                                output.RedeemScript,
                                txscript.SigHashAll,
                                output.PrivateKey,
                        )

                        if err != nil {
                                return nil, err
                        }

                        transaction.TxIn[i].Witness = wire.TxWitness{signature, output.Preimage, output.RedeemScript}
                }
        }

        return transaction, nil
}

func createNestedP2shScript(redeemScript []byte) []byte {
        addressScript := []byte{
                txscript.OP_0,
                txscript.OP_DATA_32,
        }

        redeemScriptHash := sha256.Sum256(redeemScript)
        addressScript = append(addressScript, redeemScriptHash[:]...)

        return addressScript
}

func (m *Backend) GetLnurl(amount int64) string {

	str1 := "https://the.submarine-swap-one.click:5891/lnw?k1="
	k1_4 := make([]byte, 4)
	rand.Read(k1_4[:])
	str2 := hex.EncodeToString(k1_4)
	m.k1 = str2
	str3 := "&sat="
	str4 := fmt.Sprintf("%d", amount)

	all := str1 + str2 + str3 + str4
	ret, err := lnurl.LNURLEncode(all)
	if err != nil { logging.Errorf("lnurl encode error: %s\n", err) }

        return ret
}

func (m *Backend) GetSatmax() int64 {
	sat_max := m.gsat_max
	if sat_max > 100000 {
		sat_max = 100000
	}

        return sat_max
}

func (m *Backend) GetExstr() string {
        return m.ex_str
}

func (m *Backend) SendSubmarine(password string) []string {

	if !keyfile.TestPassword(password) {
                return []string{"Wrong OCM password"}
        }
	invoice, sat_inv, err := getInvoice(m.k1)
	if err != nil {
		logging.Errorf("GetInvoice error: %s", err)
                return []string{"GetInvoice error"}
	}
        logging.Infof("Invoice: %s\n", invoice)

	if m.gsat_max == 0 {
                return []string{"Too low Spendable Balance"}
	}

	refundPath := filepath.Join(util.DataDirectory(), "refund.txt")
	if _, err := os.Stat(refundPath); err == nil {
                return []string{"Wait six hours before your next swap"}
	}

        if !strings.HasPrefix(invoice, "lnbc") {
                return []string{"Incorrect LN invoice syntax"}
	}

	if strings.HasPrefix(invoice, "lnbc1p") {
                return []string{"Zero-amount LN invoice - not suitable for submarine swap"}
	}

	refundOld := filepath.Join(util.DataDirectory(), "refund.old")
	if _, err := os.Stat(refundOld); (err != nil && sat_inv < 10000 ) {
                return []string{"Initial top-up of Phoenix Wallet must be at least 10,000 sat"}
	}

	if sat_inv > 100000 {
                return []string{"Please use up to 100,000 sat"}
	}

	var tmpstr string
	if sat_inv > m.gsat_max {
		tmpstr = "Not enough funds for: " + fmt.Sprintf("%d", sat_inv) + " sat"
                return []string{tmpstr}
	}

	pubkey := keyfile.GetPublicKey()
	hex_pubkey := hex.EncodeToString(pubkey)

	text_sp, addr_sp, err := SubPost(invoice, hex_pubkey)
	if err != nil {
                return []string{addr_sp}
	}

	if strings.HasPrefix(text_sp, "Err") {
                return []string{addr_sp}
	}

	vtc_inv, err := strconv.ParseInt(text_sp, 10, 64)
	if err != nil { logging.Errorf("parse int error: %s\n", err) }

	m.PrepareSweepSub(vtc_inv, addr_sp)
	txids := m.SendSweepSub(password)

	m.gsat_max = 1
	m.ex_str = "0 @ 0"

	return txids
}

func getInvoice(k1 string) (string, int64, error) {
	url := "https://the.submarine-swap-one.click:5891/ocm?k1="
	url += k1
        resp, err := http.Get(url)
        if err != nil {
		logging.Errorf("http.Get error: %s", err)
		return "getInvoice error", 0, err
	}

        defer resp.Body.Close()
        bodyBytes, _ := ioutil.ReadAll(resp.Body)

        var inv_resp InvoiceResponse
        json.Unmarshal(bodyBytes, &inv_resp)

	resp_len := len(inv_resp.Invoice)
        if resp_len == 0 {
                logging.Errorf("Invoice size zero\n")
		err := errors.New("Invoice size zero")
		return "Invoice size zero", 0, err
	}

	return inv_resp.Invoice, inv_resp.Amount, nil
}
