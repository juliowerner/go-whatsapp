package whatsapp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/Rhymen/go-whatsapp/binary"
	"github.com/Rhymen/go-whatsapp/crypto/cbc"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
)

func (wac *Conn) readPump() {
	defer func() {
		fmt.Println("Defer function")
		wac.wg.Done()
		fmt.Println("wait group done sent, trying to disconnect again")
		_, _ = wac.Disconnect()
		fmt.Println("Disconnected")
	}()

	var readErr error
	var msgType int
	var reader io.Reader

	for {
		readerFound := make(chan struct{})
		go func() {
			msgType, reader, readErr = wac.ws.conn.NextReader()
			close(readerFound)
			fmt.Println("New message to read")
		}()
		select {
		case <-readerFound:
			if readErr != nil {
				fmt.Println("Error receiving message")
				wac.handle(&ErrConnectionFailed{Err: readErr})
				fmt.Println("Error receiving message killing read pump")
				return
			}
			fmt.Println("Reading message")
			msg, err := ioutil.ReadAll(reader)
			if err != nil {
				fmt.Println("Error reading message")
				wac.handle(errors.Wrap(err, "error reading message from Reader"))
				fmt.Println("Error reading continuing")
				continue
			}
			fmt.Println("Processing Message")
			err = wac.processReadData(msgType, msg)
			if err != nil {
				fmt.Println("Error Processing Message")
				wac.handle(errors.Wrap(err, "error processing data"))
			}
			fmt.Println("Processing Message Done")
		case <-wac.ws.close:
			fmt.Println("Read pump received close signal, returning")
			return
		}
	}
}

func (wac *Conn) processReadData(msgType int, msg []byte) error {
	data := strings.SplitN(string(msg), ",", 2)

	if data[0][0] == '!' { //Keep-Alive Timestamp
		data = append(data, data[0][1:]) //data[1]
		data[0] = "!"
	}

	if len(data) != 2 || len(data[1]) == 0 {
		return ErrInvalidWsData
	}

	wac.listener.RLock()
	listener, hasListener := wac.listener.m[data[0]]
	wac.listener.RUnlock()

	if hasListener {
		// listener only exists for TextMessages query messages out of contact.go
		// If these binary query messages can be handled another way,
		// then the TextMessages, which are all JSON encoded, can directly
		// be unmarshalled. The listener chan could then be changed from type
		// chan string to something like chan map[string]interface{}. The unmarshalling
		// in several places, especially in session.go, would then be gone.
		listener <- data[1]

		wac.listener.Lock()
		delete(wac.listener.m, data[0])
		wac.listener.Unlock()
	} else if msgType == websocket.BinaryMessage {
		wac.loginSessionLock.RLock()
		sess := wac.session
		wac.loginSessionLock.RUnlock()
		if sess == nil || sess.MacKey == nil || sess.EncKey == nil {
			return ErrInvalidWsState
		}
		message, err := wac.decryptBinaryMessage([]byte(data[1]))
		if err != nil {
			return errors.Wrap(err, "error decoding binary")
		}
		wac.dispatch(message)
	} else { //RAW json status updates
		wac.handle(string(data[1]))
	}
	return nil
}

func (wac *Conn) decryptBinaryMessage(msg []byte) (*binary.Node, error) {
	//message validation
	h2 := hmac.New(sha256.New, wac.session.MacKey)
	if len(msg) < 33 {
		var response struct {
			Status int `json:"status"`
		}
		err := json.Unmarshal(msg, &response)
		if err == nil {
			if response.Status == 404 {
				return nil, ErrServerRespondedWith404
			}
			return nil, errors.New(fmt.Sprintf("server responded with %d", response.Status))
		} else {
			return nil, ErrInvalidServerResponse
		}

	}
	h2.Write([]byte(msg[32:]))
	if !hmac.Equal(h2.Sum(nil), msg[:32]) {
		return nil, ErrInvalidHmac
	}

	// message decrypt
	d, err := cbc.Decrypt(wac.session.EncKey, nil, msg[32:])
	if err != nil {
		return nil, errors.Wrap(err, "decrypting message with AES-CBC failed")
	}

	// message unmarshal
	message, err := binary.Unmarshal(d)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode binary")
	}

	return message, nil
}
