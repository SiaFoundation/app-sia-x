package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"

	"gitlab.com/NebulousLabs/Sia/types"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) != 3 {
		log.Fatal("Usage: ./txn2bin txn.json txn.bin")
	}
	js, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	var txn types.Transaction
	if err := json.Unmarshal(js, &txn); err != nil {
		log.Fatal(err)
	}
	f, err := os.Create(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if err := txn.MarshalSia(f); err != nil {
		log.Fatal(err)
	}
}
