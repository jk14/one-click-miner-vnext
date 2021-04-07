package wallet

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"bytes"
        "encoding/hex"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
	"github.com/vertcoin-project/one-click-miner-vnext/logging"
	"github.com/vertcoin-project/one-click-miner-vnext/networks"
	"github.com/vertcoin-project/one-click-miner-vnext/util"
	"github.com/vertcoin-project/one-click-miner-vnext/util/bech32"
	"github.com/vertcoin-project/one-click-miner-vnext/keyfile"
)

func (w *Wallet) PrepareSweepSubWal(vtc_inv int64, addr string) ([]*wire.MsgTx, error) {
        utxos, err := w.Utxos()
        if err != nil {
                return nil, errors.New("backend_failure")
        }
        retArr := make([]*wire.MsgTx, 0)
        for {
                tx := wire.NewMsgTx(2)
                totalIn := uint64(0)
                for _, u := range utxos {
                        alreadyIncluded := false
                        for _, t := range retArr {
                                for _, i := range t.TxIn {
                                        if i.PreviousOutPoint.Hash.String() == u.TxID && i.PreviousOutPoint.Index == uint32(u.Vout) {
                                                alreadyIncluded = true
                                                break
                                        }
                                }
                        }
                        if alreadyIncluded {
                                logging.Debugf("UTXO Already Included: %v", u)
                                continue
                        }
                        totalIn += u.Amount
                        h, _ := chainhash.NewHashFromStr(u.TxID)
                        tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(h, uint32(u.Vout)), w.Script, nil))
                }

                if len(tx.TxIn) == 0 {
                        logging.Warnf("Trying to sweep with zero UTXOs")
                        return nil, errors.New("insufficient_funds")
                }

                ocm_addr := keyfile.GetAddress()
                hash, version, err := base58.CheckDecode(ocm_addr)
                if err == nil && version == networks.Active.Base58P2PKHVersion {
                        pubKeyHash := hash
                        if err != nil {
                                return nil, fmt.Errorf("invalid_address")
                        }
                        if len(pubKeyHash) != 20 {
                                return nil, fmt.Errorf("invalid_address")
                        }
                        p2pkhScript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_DUP).
                                AddOp(txscript.OP_HASH160).AddData(pubKeyHash).
                                AddOp(txscript.OP_EQUALVERIFY).AddOp(txscript.OP_CHECKSIG).Script()
                        if err != nil {
                                return nil, fmt.Errorf("script_failure")
                        }
                        tx.AddTxOut(wire.NewTxOut(0, p2pkhScript))
                } else if err == nil && version == networks.Active.Base58P2SHVersion {
                        scriptHash := hash
                        if err != nil {
                                return nil, fmt.Errorf("invalid_address")
                        }
                        if len(scriptHash) != 20 {
                                return nil, fmt.Errorf("invalid_address")
                        }
                        p2shScript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_HASH160).AddData(scriptHash).AddOp(txscript.OP_EQUAL).Script()
                        if err != nil {
                                return nil, fmt.Errorf("script_failure")
                        }
                        tx.AddTxOut(wire.NewTxOut(0, p2shScript))
                } else if strings.HasPrefix(ocm_addr, fmt.Sprintf("%s1", networks.Active.Bech32Prefix)) {
                        script, err := bech32.SegWitAddressDecode(ocm_addr)
                        if err != nil {
                                return nil, fmt.Errorf("invalid_address")
                        }
                        tx.AddTxOut(wire.NewTxOut(int64(totalIn), script))
                } else {
                        return nil, fmt.Errorf("invalid_address")
                }

                sub_script, err := bech32.SegWitAddressDecode(addr)
                if err != nil {
                        return nil, fmt.Errorf("invalid_address2")
                }
                tx.AddTxOut(wire.NewTxOut(vtc_inv, sub_script))

                for i := range tx.TxIn {
                        tx.TxIn[i].SignatureScript = make([]byte, 107) // add dummy signature to properly calculate size
                }

                // Weight = (stripped_size * 4) + witness_size formula,
                // using only serialization with and without witness data. As witness_size
                // is equal to total_size - stripped_size, this formula is identical to:
                // weight = (stripped_size * 3) + total_size.
                logging.Debugf("Transaction raw serialize size is %d\n", tx.SerializeSize())
                logging.Debugf("Transaction serialize size stripped is %d\n", tx.SerializeSizeStripped())

                chunked := false
                // Chunk if needed
                if tx.SerializeSize() > maxTxSize {
			return nil, errors.New("too many inputs - aggregate first")
                        chunked = true
                        // Remove some extra inputs so we have enough for the next TX to remain valid, we
                        // want to have enough money to create an output with enough value
                        valueRemoved := uint64(0)
                        for tx.SerializeSize() > maxTxSize || valueRemoved < 100000 {
                                for _, u := range utxos {
                                        if u.TxID == tx.TxIn[len(tx.TxIn)-1].PreviousOutPoint.Hash.String() &&
                                                uint32(u.Vout) == tx.TxIn[len(tx.TxIn)-1].PreviousOutPoint.Index {
                                                totalIn -= u.Amount
                                                valueRemoved += u.Amount
                                        }
                                }
                                tx.TxIn = tx.TxIn[:len(tx.TxIn)-1]
                        }
                }

                txWeight := (tx.SerializeSizeStripped() * 3) + tx.SerializeSize()
                logging.Debugf("Transaction weight is %d\n", txWeight)
                btcTx := btcutil.NewTx(tx)

                sigOpCost, err := w.GetSigOpCost(btcTx, w.Script, false, true, true)
                if err != nil {
                        return nil, fmt.Errorf("could_not_calculate_fee")
                }
                logging.Debugf("Transaction sigop cost is %d\n", sigOpCost)

                vSize := (math.Max(float64(txWeight), float64(sigOpCost*20)) + float64(3)) / float64(4)
                logging.Debugf("Transaction vSize is %.4f\n", vSize)
                vSizeInt := uint64(vSize + float64(0.5)) // Round Up
                logging.Debugf("Transaction vSizeInt is %d\n", vSizeInt)

                fee := uint64(vSizeInt * 100)
                logging.Debugf("Setting fee to %d\n", fee)

                // empty out the dummy sigs
                for i := range tx.TxIn {
                        tx.TxIn[i].SignatureScript = nil
                }

                u_vtc_inv := uint64(vtc_inv)
                tx.TxOut[0].Value = int64(totalIn - fee - u_vtc_inv)
                if tx.TxOut[0].Value < 50000 {
                        return nil, fmt.Errorf("insufficient_funds")
                }
                retArr = append(retArr, tx)

                if !chunked {
                        break
                }
        }
        return retArr, nil
}

func (w *Wallet) SendSub(tx *wire.MsgTx) (string, string, error) {
        var b bytes.Buffer
        tx.Serialize(&b)
        s := txSend{
                RawTx: hex.EncodeToString(b.Bytes()),
        }

        r := txSendReply{}

        err := util.PostJson(fmt.Sprintf("%stx", networks.Active.OCMBackend), s, &r)
        if err != nil {
                return "", "", err
        }

        return r.TxId, hex.EncodeToString(b.Bytes()), err
}

func (w *Wallet) SendRef(txref string) (string, error) {
        s := txSend{
                RawTx: txref,
        }

        r := txSendReply{}

        err := util.PostJson(fmt.Sprintf("%stx", networks.Active.OCMBackend), s, &r)
        if err != nil {
                return "", err
        }

        return r.TxId, err
}

