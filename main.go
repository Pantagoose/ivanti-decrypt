package main

import (
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
)

// aeskey to gen_key
func swapBytes(x uint32) uint32 {
	return (x>>24)&0xff | (x>>8)&0xff00 | (x<<8)&0xff0000 | (x<<24)&0xff000000
}

func getKey(input string) [16]byte {
	var aesKey [16]byte

	if len(input) != 32 {
		os.Exit(0)
	}

	var data [4]uint32
	for i := 0; i < 4; i++ {
		part := input[i*8 : (i+1)*8]
		bytes, err := hex.DecodeString(part)
		if err != nil {
			log.Fatal(err)
		}
		data[i] = binary.BigEndian.Uint32(bytes)
	}

	// swap bytes (simulate C-style little-endian swap)
	for i := 0; i < 4; i++ {
		data[i] = swapBytes(data[i])
	}

	// XOR transformations
	data[1] ^= 0xAEEF41FE
	data[0] ^= 0x99ED2BF2
	data[2] ^= 0x141058C7
	data[3] ^= 0xD2ED180E

	// Fill aesKey
	for k := 0; k < 4; k++ {
		for m := 0; m < 4; m++ {
			aesKey[4*k+m] = byte(data[k] >> (8 * m))
		}
	}

	return aesKey
}

// decrypt sector
func xorBytes(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func ivantiCBC(key [16]byte, sector uint64, data []byte) []byte {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		log.Fatal(err)
	}

	iv := make([]byte, 16)
	binary.LittleEndian.PutUint64(iv, sector)

	preIV := make([]byte, 16)
	block.Decrypt(preIV, iv)

	result := make([]byte, 0, len(data))
	for i := 0; i < len(data); i += 16 {
		chunk := data[i : i+16]
		ciphertext := xorBytes(chunk, preIV)

		plaintext := make([]byte, 16)
		block.Decrypt(plaintext, ciphertext)

		out := xorBytes(plaintext, iv)
		result = append(result, out...)

		copy(iv, ciphertext)
	}

	return result
}

func main() {
	if len(os.Args) != 4 {
		fmt.Printf("Usage: %s <input_file> <output_file> <aes_key_hex>\n", os.Args[0])
		os.Exit(1)
	}

	inputFile := os.Args[1]
	outputFile := os.Args[2]
	key := getKey(os.Args[3])

	in, err := os.Open(inputFile)
	if err != nil {
		log.Fatalf("Failed to open input file: %v", err)
	}
	defer in.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer out.Close()

	sectorSize := 512
	buf := make([]byte, sectorSize)
	var sector uint64

	for {
		n, err := io.ReadFull(in, buf)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			log.Fatalf("Failed to read input file: %v", err)
		}

		dec := ivantiCBC(key, sector, buf[:n])
		_, err = out.Write(dec)
		if err != nil {
			log.Fatalf("Failed to write to output file: %v", err)
		}

		sector++
	}

	fmt.Println("Decryption complete.")
}

