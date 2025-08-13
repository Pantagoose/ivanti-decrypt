# About ivanti-decrypt
Disk image decryptor for both Ivanti and Pulse Secure Appliances. 
This tool is used as part of the main decryption process mentioned in this blog: https://pantagoose.hashnode.dev/pulse-secure-ivanti-vpn-kernel-decryption-for-investigation.

# Building
You would need to download go on your system, and build it with the following command:
```
$ go build main.go
```

# Usage
```
$ ./main <input_file> <output_file> <aes_key_hex>
```
More information and example usage are shown [here](https://pantagoose.hashnode.dev/pulse-secure-ivanti-vpn-kernel-decryption-for-investigation#heading-step-5-initial-testing-on-partition-segment-using-decryption-key).
