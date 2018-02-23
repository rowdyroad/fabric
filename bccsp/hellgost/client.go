package hellgost

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
)

var clientInstance = NewClient(os.Getenv("HELLGOST_ADDRESS"), false)

func GetClient() *Client {
	return clientInstance
}

type Client struct {
	sync.Mutex
	address string
	client  net.Conn
}

func NewClient(address string, auto bool) *Client {
	client := &Client{address: address}
	if auto {
		client.getClient()
	}
	return client
}

type request struct {
	Method string
	Args   interface{}
}

type response struct {
	Response json.RawMessage
	Error    error
}

func (c *Client) getClient() net.Conn {
	if c.client == nil {
		var err error
		c.client, err = net.Dial("tcp", c.address)
		if err != nil {
			panic(fmt.Errorf("Error: connection error: %s", err.Error()))
		}
	}
	return c.client
}

func (c *Client) sendCommand(data string) string {
	c.Lock()
	defer c.Unlock()
	conn := c.getClient()
	if _, err := fmt.Fprint(conn, data+"\n"); err != nil {
		panic(err)
	}
	if response, err := bufio.NewReader(conn).ReadString('\n'); err == nil {
		return response
	} else {
		panic(err)
	}
}

func (c *Client) call(method string, args interface{}, reply interface{}) error {
	req := request{method, args}
	data, err := json.Marshal(req)
	if err != nil {
		panic(err)
	}

	message := c.sendCommand(base64.StdEncoding.EncodeToString(data))

	data, err = base64.StdEncoding.DecodeString(message)
	if err != nil {
		panic(err)
	}

	var resp response
	err = json.Unmarshal(data, &resp)
	if err != nil {
		panic(fmt.Errorf("Error: ", err, string(data)))
	}
	if resp.Error != nil {
		return resp.Error
	}
	err = json.Unmarshal(resp.Response, reply)
	if err != nil {
		panic(err)
	}

	return nil
}

func (c *Client) Hash(data []byte) ([]byte, error) {
	var hash []byte
	err := c.call("HellGost.Hash", Hash{Data: data}, &hash)
	return hash, err
}

func (c *Client) Hash512(data []byte) ([]byte, error) {
	var hash []byte
	err := c.call("HellGost.Hash512", Hash{Data: data}, &hash)
	return hash, err
}

func (c *Client) Verify(key string, data []byte, sign []byte) (bool, error) {
	var ret bool
	err := c.call("HellGost.Verify", Verify{Key: key, Data: data, Sign: sign}, &ret)
	return ret, err
}

func (c *Client) Sign(key string, data []byte) ([]byte, error) {
	var sign []byte
	err := c.call("HellGost.Sign", Sign{Key: key, Data: data}, &sign)
	return sign, err
}

func (c *Client) GenKey(key string) error {
	var ret bool
	err := c.call("HellGost.GenKey", GenKey{Key: key}, &ret)
	return err
}

func (c *Client) Close() {
	if c.client != nil {
		c.client.Close()
	}
}
