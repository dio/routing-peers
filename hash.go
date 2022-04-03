package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func main() {
	args := os.Args[1:]
	b, err := os.ReadFile(args[0])
	if err != nil {
		log.Fatal("failed to read file:", err)
	}
	block, _ := pem.Decode(b)
	h := sha256.New()
	h.Write(block.Bytes)
	fmt.Println(hex.EncodeToString(h.Sum(nil)))
}
