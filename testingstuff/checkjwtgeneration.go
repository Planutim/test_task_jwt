package main

import (
	"encoding/base64"
	"fmt"
)

func main() {
	msg := "Hi man!"
	encoded := base64.StdEncoding.EncodeToString([]byte(msg))
	fmt.Println(encoded)
}
