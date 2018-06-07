package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	"github.com/NebulousLabs/Sia/types"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) != 3 {
		log.Fatal("Usage: ./txnSigHash [index] [txn]")
	}
	js, err := ioutil.ReadFile(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	var txn types.Transaction
	err = json.Unmarshal(js, &txn)
	if err != nil {
		log.Fatal(err)
	}
	index, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(txn.SigHash(index))
}
