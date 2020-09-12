package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"golang.org/x/crypto/pbkdf2"
)

var (
	counter uint64
	wg      sync.WaitGroup
)

type Config struct {
	Username, ServerKey, Salt, Passfile string
	Threads                             int
}

func ScramSHA1ServerKey(username, password string, salt []byte) (ServerKey []byte) {

	prehash := md5.Sum([]byte(fmt.Sprintf("%s:mongo:%s", username, password)))
	pwdMd5 := hex.EncodeToString(prehash[:])
	hashedPwd := pbkdf2.Key([]byte(pwdMd5), salt, 10000, 20, sha1.New)

	preServerKey := hmac.New(sha1.New, hashedPwd)
	preServerKey.Write([]byte("Server Key"))

	return preServerKey.Sum(nil)
}

func readStreamFromS3(bucket string, object string) (*bufio.Reader, error) {
	var awsSess = session.Must(session.NewSession())
	region, err := s3manager.GetBucketRegion(context.Background(), awsSess, bucket, "us-west-2")
	awsS3 := s3.New(awsSess, aws.NewConfig().WithRegion(region))
	req, err := awsS3.GetObject(&s3.GetObjectInput{Bucket: &bucket, Key: &object})
	if err != nil {
		return nil, err
	}
	gzipReader, err := gzip.NewReader(req.Body)
	if err != nil {
		return nil, err
	}
	defer req.Body.Close()
	defer gzipReader.Close()
	lineReader := bufio.NewReader(gzipReader)
	return lineReader, nil
}

func passwordProducer(filename string, passwordChan chan string) {
	defer close(passwordChan)
	if strings.HasPrefix(filename, "s3://") {
		u, err := url.Parse(filename)
		if err != nil {
			log.Fatal(fmt.Sprintf("S3 URL invalid: %s", err))
		}
		bucket := u.Host
		object := u.Path
		//log.Printf("%s %s", bucket, object)
		lineReader, err := readStreamFromS3(bucket, object)
		if err != nil {
			log.Fatal(fmt.Sprintf("Unable to read from s3: %s", err))
		}
		for {
			line, _, err := lineReader.ReadLine()
			if err == io.EOF {
				break
			}
			passwordChan <- string(line)
		}
	} else {

		var scanner *bufio.Scanner
		if filename != "-" {
			file, err := os.Open(filename)
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()
			scanner = bufio.NewScanner(file)
		} else {
			scanner = bufio.NewScanner(os.Stdin)
		}

		for scanner.Scan() {
			passwordChan <- scanner.Text()
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}
}

func inArray(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func worker(wg *sync.WaitGroup, config *Config, passwordChan chan string) {
	defer wg.Done()
	fmt.Println("Starting worker")
	bytesalt, err := base64.StdEncoding.DecodeString(config.Salt)
	byteServerKey, err := base64.StdEncoding.DecodeString(config.ServerKey)
	if err != nil {
		log.Fatal("base64 decode error:", err)
	}
	count := 0

	for {

		select {
		case password, ok := <-passwordChan:
			if !ok {
				log.Println("Finished reading dictionary")
				return
			}
			count++
			if count%1000 == 0 {
				atomic.AddUint64(&counter, 1000)
				count = 0
			}

			calcServKey := ScramSHA1ServerKey(config.Username, password, bytesalt)
			if bytes.Compare(byteServerKey, calcServKey) == 0 {
				log.Fatal("Found password:", password)
			}
		}
	}
}

func genStat() {
	start := time.Now()
	time.Sleep(1 * time.Second)
	for {
		exp := time.Since(start)
		fmt.Print("\033[u\033[K")
		fmt.Printf("\rTime passed: %s Avg speed %f per second", exp.String(), float64(atomic.LoadUint64(&counter))/exp.Seconds())
		time.Sleep(2 * time.Second)
	}
}

func main() {
	GlobalConfig := &Config{}
	flag.StringVar(&GlobalConfig.Username, "username", "", "Username")
	flag.StringVar(&GlobalConfig.ServerKey, "serverkey", "", "Server Key")
	flag.StringVar(&GlobalConfig.Salt, "salt", "", "Salt")
	flag.StringVar(&GlobalConfig.Passfile, "passfile", "", "location of password file, use '-' for STDIN")
	flag.IntVar(&GlobalConfig.Threads, "threads", 8, "number of workers per machine")
	flag.Parse()
	if GlobalConfig.Username == "" || GlobalConfig.ServerKey == "" || GlobalConfig.Salt == "" || GlobalConfig.Passfile == "" {
		log.Fatal("Missing required argument")
	}
	go genStat()
	var wg sync.WaitGroup
	passwordChan := make(chan string, 1000)
	go passwordProducer(GlobalConfig.Passfile, passwordChan)
	time.Sleep(2 * time.Second)
	for i := 0; i < GlobalConfig.Threads; i++ {
		go worker(&wg, GlobalConfig, passwordChan)
		wg.Add(1)
	}

	wg.Wait()
	log.Println("FIN")
}
