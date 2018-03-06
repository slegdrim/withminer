package main

/*
#cgo CFLAGS: -Iargon2
#cgo LDFLAGS: -Largon2 -largon2
#include "argon2.h"
*/
import "C"

import "fmt"
import "time"
import "math"
import "strings"
import "bytes"
import "io/ioutil"
import "encoding/json"
import "net/http"
import "net/url"
import "strconv"
import "sync"
import "math/rand"
import "encoding/base64"
import "crypto/sha512"
import "hash"
import "math/big"
import "flag"
import "os"
import "runtime"
import "github.com/mr-tron/base58/base58"

var ARGON2_T_COST C.uint = 1
var ARGON2_M_COST C.uint = 524288
var ARGON2_PARALLELISM C.uint = 1
var ARGON2_SALT_LENGTH_UINT C.uint = 16
var ARGON2_HASH_LENGTH_UINT C.uint = 32
var ARGON2_SALT_LENGTH_ULL C.ulonglong = 16
var ARGON2_HASH_LENGTH_ULL C.ulonglong = 32
var ARGON2_VERSION C.uint = 0x13

var SALT_LENGTH int = 16
var NONCE_LENGTH int = 32
var HASH_LENGTH int = 32

var UPDATE_DELAY_TIME time.Duration = 2000
var WORK_DELAY_TIME time.Duration = 2000

var DEFAULT_HOSTNAME string = "http://aropool.com"
var DEFAULT_PRIVATE_KEY string = "5zn6cMedKZ2cenTcLNTmtK7dJZDXA8w4m9pxg1qsS5SDjugvAxtWf8vBaK6LMK5wSGDtrhT3KJrrHXwWshyuvyPb"

var gvCoinName string = ""
var gvHostName string = ""
var gvPrivateKey string = ""
var gvWorkerId string = ""
var gvHashRate float64 = 1
var gvWorkerCount int = 1
var gvTotalHashRate float64 = 0

type WorkerInfo struct {
	workerNumber int
	hashRate     float64
}

var gvWorkerInfos []WorkerInfo

var gvDifficultyFloat64 float64 = 0
var gvDifficultyBigInt *big.Int = big.NewInt(0)
var gvDifficultyString = ""
var gvBlock string = ""
var gvHeight float64 = 0
var gvPublicKey string = ""
var gvLimit float64 = 0

var gvArgon2EncodedLength C.ulonglong = 0

var gvUpdateRequestCount uint64 = 0
var gvUpdateSuccessCount uint64 = 0
var gvUpdateErrorCount uint64 = 0

var gvWorkHashCount uint64 = 0

var gvSubmitRequestCount uint64 = 0
var gvSubmitSuccessCount uint64 = 0
var gvSubmitErrorCount uint64 = 0

func makeWorkId() {
	var ns float64 = (float64(time.Now().UnixNano()) / 10) / 10000
	gvWorkerId = fmt.Sprintf("%8x%05x", int64(math.Floor(ns)), int64(ns-math.Floor(ns))*1000000)
}

func makeArgon2EncodedLength() {
	gvArgon2EncodedLength = C.argon2_encodedlen(ARGON2_T_COST, ARGON2_M_COST, ARGON2_PARALLELISM, ARGON2_SALT_LENGTH_UINT, ARGON2_HASH_LENGTH_UINT, C.Argon2_i)
}

func getInfoUrl() string {
	var buffer bytes.Buffer
	buffer.WriteString(gvHostName)
	buffer.WriteString("/mine.php?q=info")

	buffer.WriteString("&worker=")
	buffer.WriteString(gvWorkerId)

	buffer.WriteString("&address=")
	buffer.WriteString(gvPrivateKey)

	buffer.WriteString("&hashrate=")
	buffer.WriteString(string(int64(math.Floor(gvHashRate))))

	return buffer.String()
}

func updateMiningInfo() {
	for {

		gvUpdateRequestCount = gvUpdateRequestCount + 1

		response, responseError := http.Get(getInfoUrl())
		if responseError != nil {
			gvUpdateErrorCount = gvUpdateErrorCount + 1
			time.Sleep(UPDATE_DELAY_TIME * time.Millisecond)
			continue
		}

		defer response.Body.Close()

		responseBody, readError := ioutil.ReadAll(response.Body)
		if readError != nil {
			gvUpdateErrorCount = gvUpdateErrorCount + 1
			time.Sleep(UPDATE_DELAY_TIME * time.Millisecond)
			continue
		}

		var jsonString string = string(responseBody)

		//var jsonString string = `{"data":{"difficulty":"38185896","public_key":"PZ8Tyr4Nx8MHsRAGMpZmZ6TWY63dXWSCy7AEg3h9oYjeR74yj73q3gPxbxq9R3nxSSUV4KKgu1sQZu9Qj9v2q2HhT5H3LTHwW7HzAA28SjWFdzkNoovBMncD","limit":350000,"block":"2TtGipPCXTWSEh4NRob4Mw5QEKEETY4744F7MqkSqfwL4E4QL7igARD48H3dc7NubMv7Hezn8c1PFCkXCvEZ1Z2F","height":19618},"status":"ok","coin":"arionum"}`

		jsonDecoder := json.NewDecoder(strings.NewReader(jsonString))

		type MiningInfo struct {
			Status string
			Data   map[string]interface{}
			Coin   string
		}

		var miningInfo MiningInfo

		decodeError := jsonDecoder.Decode(&miningInfo)
		if decodeError != nil {
			gvUpdateErrorCount = gvUpdateErrorCount + 1
			time.Sleep(UPDATE_DELAY_TIME * time.Millisecond)
			continue
		}

		if miningInfo.Status != "ok" {
			gvUpdateErrorCount = gvUpdateErrorCount + 1
			time.Sleep(UPDATE_DELAY_TIME * time.Millisecond)
			continue
		}

		if miningInfo.Data["block"] == nil {
			gvUpdateErrorCount = gvUpdateErrorCount + 1
			time.Sleep(UPDATE_DELAY_TIME * time.Millisecond)
			continue
		}

		if miningInfo.Data["public_key"] == nil {
			gvUpdateErrorCount = gvUpdateErrorCount + 1
			time.Sleep(UPDATE_DELAY_TIME * time.Millisecond)
			continue
		}

		if miningInfo.Data["height"] == nil {
			gvUpdateErrorCount = gvUpdateErrorCount + 1
			time.Sleep(UPDATE_DELAY_TIME * time.Millisecond)
			continue
		}

		if miningInfo.Data["limit"] == nil {
			gvUpdateErrorCount = gvUpdateErrorCount + 1
			time.Sleep(UPDATE_DELAY_TIME * time.Millisecond)
			continue
		}

		if miningInfo.Data["difficulty"] == nil {
			gvUpdateErrorCount = gvUpdateErrorCount + 1
			time.Sleep(UPDATE_DELAY_TIME * time.Millisecond)
			continue
		}

		gvBlock = miningInfo.Data["block"].(string)
		gvPublicKey = miningInfo.Data["public_key"].(string)
		gvHeight = miningInfo.Data["height"].(float64)
		gvLimit = miningInfo.Data["limit"].(float64)
		gvDifficultyString = miningInfo.Data["difficulty"].(string)

		difficulty, parseError := strconv.ParseFloat(miningInfo.Data["difficulty"].(string), 64)
		if parseError != nil {
			difficulty = 0
		}

		gvDifficultyFloat64 = difficulty
		gvDifficultyBigInt.SetString(gvDifficultyString, 10)

		gvUpdateSuccessCount = gvUpdateSuccessCount + 1

		time.Sleep(UPDATE_DELAY_TIME * time.Millisecond)
	}
}

func makeModifiedNonce() string {
	var nonce []byte = make([]byte, NONCE_LENGTH)

	rand.Read(nonce)

	var encodedNonce string = base64.StdEncoding.EncodeToString(nonce)
	var encodedNonceLength int = len(encodedNonce)

	var modifiedNonceBuffer bytes.Buffer
	for i := 0; i < encodedNonceLength; i++ {
		if (encodedNonce[i] >= '0' && encodedNonce[i] <= '9') ||
			(encodedNonce[i] >= 'a' && encodedNonce[i] <= 'z') ||
			(encodedNonce[i] >= 'A' && encodedNonce[i] <= 'Z') {
			modifiedNonceBuffer.WriteByte(encodedNonce[i])
		}
	}

	return modifiedNonceBuffer.String()
}

func makeArgon2Input(modifiedNonce string) string {
	var buffer bytes.Buffer
	buffer.WriteString(gvPublicKey)
	buffer.WriteString("-")

	buffer.WriteString(modifiedNonce)
	buffer.WriteString("-")

	buffer.WriteString(gvBlock)
	buffer.WriteString("-")

	buffer.WriteString(gvDifficultyString)

	return buffer.String()
}

func callArgon2Hash(argon2InputString string) string {
	var argon2InputLength C.ulonglong = C.ulonglong(len(argon2InputString))

	var argon2Hash []byte = make([]byte, HASH_LENGTH)
	var salt []byte = make([]byte, SALT_LENGTH)
	var argon2EncodedHash []byte = make([]byte, gvArgon2EncodedLength)

	rand.Read(salt)

	argon2EncodedHashResult := C.CString(string(argon2EncodedHash))

	C.argon2_hash(
		ARGON2_T_COST,
		ARGON2_M_COST,
		ARGON2_PARALLELISM,
		C.CBytes([]byte(argon2InputString)),
		argon2InputLength,
		C.CBytes(salt),
		ARGON2_SALT_LENGTH_ULL,
		C.CBytes(argon2Hash),
		ARGON2_HASH_LENGTH_ULL,
		argon2EncodedHashResult,
		gvArgon2EncodedLength,
		C.Argon2_i,
		ARGON2_VERSION)

	return C.GoString(argon2EncodedHashResult)
}

func makeNonceBigInt(sha512Input []byte) *big.Int {
	var shaHasher hash.Hash = sha512.New()

	var sha512Bytes []byte

	// Argon2 -> sha 512
	shaHasher.Reset()
	shaHasher.Write(sha512Input)
	sha512Bytes = shaHasher.Sum(nil)

	// 5 times sha 512
	for i := 0; i < 5; i++ {
		shaHasher.Reset()
		shaHasher.Write(sha512Bytes)
		sha512Bytes = shaHasher.Sum(nil)
	}

	var numberBuffer bytes.Buffer
	numberBuffer.WriteString(strconv.Itoa(int(sha512Bytes[10] & 0xFF)))
	numberBuffer.WriteString(strconv.Itoa(int(sha512Bytes[15] & 0xFF)))
	numberBuffer.WriteString(strconv.Itoa(int(sha512Bytes[20] & 0xFF)))
	numberBuffer.WriteString(strconv.Itoa(int(sha512Bytes[23] & 0xFF)))
	numberBuffer.WriteString(strconv.Itoa(int(sha512Bytes[31] & 0xFF)))
	numberBuffer.WriteString(strconv.Itoa(int(sha512Bytes[40] & 0xFF)))
	numberBuffer.WriteString(strconv.Itoa(int(sha512Bytes[45] & 0xFF)))
	numberBuffer.WriteString(strconv.Itoa(int(sha512Bytes[55] & 0xFF)))

	number := big.NewInt(0)
	number.SetString(numberBuffer.String(), 10)

	return number
}

func doWork(workNumber int) {

	var startTime int64 = 0
	var endTime int64 = 0
	var hashTime int64 = 0
	var hashTimeSum int64 = 0
	var hashCount int64 = 0
	var hashRate float64 = 0

	for {

		if gvDifficultyFloat64 == 0 {
			time.Sleep(WORK_DELAY_TIME * time.Millisecond)
			continue
		}

		startTime = time.Now().UnixNano()

		gvWorkHashCount = gvWorkHashCount + 1

		rand.Seed(time.Now().UnixNano())

		var modifiedNonce string = makeModifiedNonce()

		var argon2Input string = makeArgon2Input(modifiedNonce)

		var argon2HashResult string = callArgon2Hash(argon2Input)

		nonceBigInt := makeNonceBigInt([]byte(argon2Input + argon2HashResult))

		var localLimit float64 = float64(new(big.Int).Div(nonceBigInt, gvDifficultyBigInt).Int64())

		endTime = time.Now().UnixNano()

		hashTime = endTime - startTime

		hashCount = hashCount + 1
		hashTimeSum = hashTimeSum + hashTime

		if hashCount%5 == 0 {
			hashRate = float64(hashCount) / float64(hashTimeSum) * 1000000000

			gvWorkerInfos[workNumber].hashRate = hashRate

			hashCount = 0
			hashTimeSum = 0
		}

		if localLimit > 0 && localLimit <= gvLimit {
			go submitResult(modifiedNonce, argon2HashResult)
		}
	}
}

func submitResult(modifiedNonce string, argon2HashResult string) {
	gvSubmitRequestCount = gvSubmitRequestCount + 1

	var dataBuffer bytes.Buffer

	dataBuffer.WriteString(url.QueryEscape("argon"))
	dataBuffer.WriteString("=")
	dataBuffer.WriteString(url.QueryEscape(argon2HashResult[30:]))
	dataBuffer.WriteString("&")

	dataBuffer.WriteString(url.QueryEscape("nonce"))
	dataBuffer.WriteString("=")
	dataBuffer.WriteString(url.QueryEscape(modifiedNonce))
	dataBuffer.WriteString("&")

	dataBuffer.WriteString(url.QueryEscape("private_key"))
	dataBuffer.WriteString("=")
	dataBuffer.WriteString(url.QueryEscape(gvPrivateKey))
	dataBuffer.WriteString("&")

	dataBuffer.WriteString(url.QueryEscape("public_key"))
	dataBuffer.WriteString("=")
	dataBuffer.WriteString(url.QueryEscape(gvPublicKey))
	dataBuffer.WriteString("&")

	dataBuffer.WriteString(url.QueryEscape("address"))
	dataBuffer.WriteString("=")
	dataBuffer.WriteString(url.QueryEscape(gvPrivateKey))

	var submitUrl string = gvHostName + "/mine.php?q=submitNonce"

	response, responseError := http.Post(submitUrl, "application/x-www-form-urlencoded", bytes.NewReader(dataBuffer.Bytes()))
	if responseError != nil {
		gvSubmitErrorCount = gvSubmitErrorCount + 1
		return
	}

	defer response.Body.Close()

	responseBody, readError := ioutil.ReadAll(response.Body)
	if readError != nil {
		gvSubmitErrorCount = gvSubmitErrorCount + 1
		return
	}

	var jsonString string = string(responseBody)

	jsonDecoder := json.NewDecoder(strings.NewReader(jsonString))

	type SubmitResultInfo struct {
		Status string
	}

	var submitResultInfo SubmitResultInfo

	decodeError := jsonDecoder.Decode(&submitResultInfo)
	if decodeError != nil {
		gvSubmitErrorCount = gvSubmitErrorCount + 1
		return
	}

	if submitResultInfo.Status != "ok" {
		gvSubmitErrorCount = gvSubmitErrorCount + 1
		return
	}

	gvSubmitSuccessCount = gvSubmitSuccessCount + 1
}

func printTime() {
	t := time.Now()
	fmt.Printf("[%d-%02d-%02d %02d:%02d:%02d] ", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
}

func printStat() {

	for {
		time.Sleep(10000 * time.Millisecond)

		fmt.Println()

		printTime()
		fmt.Printf("Update Stat : %d/%d (Success/Request)\n", gvUpdateSuccessCount, gvUpdateRequestCount)

		printTime()
		fmt.Printf("Accept Stat : %d/%d (Success/Request)\n", gvSubmitSuccessCount, gvSubmitRequestCount)

		gvTotalHashRate = 0
		for i := 0; i < gvWorkerCount; i++ {
			gvTotalHashRate = gvTotalHashRate + gvWorkerInfos[i].hashRate

			printTime()
			fmt.Printf("CPU #%d : %f H/s\n", i, gvWorkerInfos[i].hashRate)
		}

		gvHashRate = math.Floor(gvTotalHashRate)
	}

}

func printStartMsg() {
	fmt.Println("*** withminer v0.1 ***")
	fmt.Println("Arionum donation address : 5zn6cMedKZ2cenTcLNTmtK7dJZDXA8w4m9pxg1qsS5SDjugvAxtWf8vBaK6LMK5wSGDtrhT3KJrrHXwWshyuvyPb")
	fmt.Println()

	printTime()
	fmt.Printf("Worker count : %d\n", gvWorkerCount)

	printTime()
	fmt.Printf("Host name : %s\n", gvHostName)

	printTime()
	fmt.Printf("Your address : %s\n", gvPrivateKey)
}

func printUsage() {
	fmt.Println("Usage of WithMiner:")
	fmt.Println("  -a [Name of coin]")
	fmt.Println("  -o [Url of miner server]")
	fmt.Println("  -u [Your address]")
	fmt.Println("  -w [Worker Count]")
	fmt.Println()
	fmt.Printf("Usage Example 1 : withminer -a arionum -o %s -u %s\n", DEFAULT_HOSTNAME, DEFAULT_PRIVATE_KEY)
	fmt.Printf("Usage Example 2 : withminer -a arionum -o %s -u %s -w %d\n", DEFAULT_HOSTNAME, DEFAULT_PRIVATE_KEY, 1)
	fmt.Println()

	// withminer -a arionum -o http://aropool.com -u 5zn6cMedKZ2cenTcLNTmtK7dJZDXA8w4m9pxg1qsS5SDjugvAxtWf8vBaK6LMK5wSGDtrhT3KJrrHXwWshyuvyPb -w 1
}

func parseFlags() int {

	paramCoinName := flag.String("a", "", "Coin name")
	paramHostName := flag.String("o", "", "Host name")
	paramAddress := flag.String("u", "", "Your Address")
	paramWorkers := flag.Int("w", 0, "Workers")

	flag.Parse()

	if *paramCoinName == "" || *paramHostName == "" || *paramAddress == "" {
		printUsage()
		return -1
	}

	decodedAddress, addressDecodeError := base58.Decode(*paramAddress)

	if addressDecodeError != nil {
		fmt.Println("Check your address!")
		return -1
	}

	if len(decodedAddress) != 64 {
		fmt.Println("Check your address!")
		return -1
	}

	gvCoinName = *paramCoinName
	gvHostName = *paramHostName
	gvPrivateKey = *paramAddress

	cpuCount := runtime.NumCPU()

	if *paramWorkers == 0 || *paramWorkers > cpuCount {
		gvWorkerCount = cpuCount
	} else {
		gvWorkerCount = *paramWorkers
	}

	return 1
}

func main() {
	flagResult := parseFlags()

	if flagResult == -1 {
		os.Exit(-1)
	}

	makeWorkId()
	makeArgon2EncodedLength()
	gvWorkerInfos = make([]WorkerInfo, gvWorkerCount)

	printStartMsg()

	var wg sync.WaitGroup
	wg.Add(1)

	go updateMiningInfo()

	for i := 0; i < gvWorkerCount; i++ {
		go doWork(i)
	}

	go printStat()

	wg.Wait()
}
