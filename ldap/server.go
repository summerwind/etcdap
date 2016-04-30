package ldap

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type ResponseWriter interface {
	Write([]byte) (int, error)
}

type Handler interface {
	ServeLDAP(ResponseWriter, *Request)
}

type Server struct {
	Addr         string
	Handler      Handler
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	TLSConfig    *tls.Config
	ErrorLog     *log.Logger
}

func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":389"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	return srv.Serve(tcpKeepAliveListener{ln.(*net.TCPListener)})
}

func (srv *Server) ListenAndServeTLS(certFile, keyFile string) error {
	// TODO
	return nil
}

func (srv *Server) Serve(l net.Listener) error {
	defer l.Close()

	var tempDelay time.Duration

	for {
		rw, e := l.Accept()

		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				srv.logf("ldap: Accept error: %v; retrying in %v", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return e
		}

		tempDelay = 0
		c := srv.newConn(rw)
		go c.serve()
	}
}

func (srv *Server) newConn(rwc net.Conn) *conn {
	c := &conn{
		server: srv,
		rwc:    rwc,
	}

	return c
}

func (s *Server) logf(format string, args ...interface{}) {
	if s.ErrorLog != nil {
		s.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

type defaultHandler struct{}

func (dh *defaultHandler) ServeLDAP(rw ResponseWriter, req *Request) {
	bindReq := req.Message.ProtocolOp.(*BindRequest)

	lr := LDAPResult{
		ResultCode:        ResultCodeSuccess,
		MatchedDN:         bindReq.Name,
		DiagnosticMessage: LDAPString{},
	}
	br := &BindResponse{lr, nil}
	msg := &LDAPMessage{
		MessageID:  req.Message.MessageID,
		ProtocolOp: br,
	}

	buf, err := msg.Bytes()
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}

	rw.Write(buf)
	fmt.Printf("Bytes: %x\n", buf)
	fmt.Println("Default handler!")
}

func NewDefaultHandler() *defaultHandler {
	return &defaultHandler{}
}

var DefaultHandler = NewDefaultHandler()

type serverHandler struct {
	srv *Server
}

func (sh serverHandler) ServeLDAP(rw ResponseWriter, req *Request) {
	handler := sh.srv.Handler
	if handler == nil {
		handler = DefaultHandler
	}
	handler.ServeLDAP(rw, req)
}

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func ListenAndServe(addr string) error {
	server := &Server{Addr: addr}
	return server.ListenAndServe()
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}

	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)

	return tc, nil
}

const bufferBeforeChunkingSize = 2048

type conn struct {
	server     *Server
	rwc        net.Conn
	remoteAddr string
	tlsState   *tls.ConnectionState
	werr       error
	r          *connReader
	bufr       *bufio.Reader
	bufw       *bufio.Writer
	mu         sync.Mutex
}

// Serve a new connection.
func (c *conn) serve() {
	c.remoteAddr = c.rwc.RemoteAddr().String()

	//defer func() {
	//	if err := recover(); err != nil {
	//		const size = 64 << 10
	//		buf := make([]byte, size)
	//		buf = buf[:runtime.Stack(buf, false)]
	//		c.server.logf("http: panic serving %v: %v\n%s", c.remoteAddr, err, buf)
	//	}
	//}()

	if tlsConn, ok := c.rwc.(*tls.Conn); ok {
		if d := c.server.ReadTimeout; d != 0 {
			c.rwc.SetReadDeadline(time.Now().Add(d))
		}

		if d := c.server.WriteTimeout; d != 0 {
			c.rwc.SetWriteDeadline(time.Now().Add(d))
		}

		if err := tlsConn.Handshake(); err != nil {
			c.server.logf("ldap: TLS handshake error from %s: %v", c.rwc.RemoteAddr(), err)
			return
		}

		c.tlsState = new(tls.ConnectionState)
	}

	c.r = &connReader{r: c.rwc}
	c.bufr = newBufioReader(c.r)
	c.bufw = newBufioWriterSize(checkConnErrorWriter{c}, 4<<10)
	fmt.Printf("Active connection: %s\n", c.remoteAddr)

	for {
		w, err := c.readRequest()

		if err != nil {
			if err == io.EOF {
				return // don't reply
			}

			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				return // don't reply
			}

			if ldaperr, ok := err.(LDAPError); ok {
				fmt.Println(ldaperr)
				//io.Write()
			}
			//io.WriteString(c.rwc, "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n400 Bad Request"+publicErr)
			return
		}

		//// HTTP cannot have multiple simultaneous active requests.[*]
		//// Until the server replies to this request, it can't read another,
		//// so we might as well run the handler in this goroutine.
		//// [*] Not strictly true: HTTP pipelining.  We could let them all process
		//// in parallel even if their responses need to be serialized.
		serverHandler{c.server}.ServeLDAP(w, w.req)
		w.finishRequest()
	}
}

// Read next request from connection.
func (c *conn) readRequest() (w *response, err error) {
	if d := c.server.ReadTimeout; d != 0 {
		c.rwc.SetReadDeadline(time.Now().Add(d))
	}

	if d := c.server.WriteTimeout; d != 0 {
		defer func() {
			c.rwc.SetWriteDeadline(time.Now().Add(d))
		}()
	}

	c.mu.Lock() // while using bufr
	req, err := readRequest(c.bufr)
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}

	req.RemoteAddr = c.remoteAddr
	req.TLS = c.tlsState

	w = &response{
		conn: c,
		req:  req,
		//reqBody:       req.Body,
		//handlerHeader: make(Header),
		//contentLength: -1,
	}
	w.cw.res = w
	w.w = newBufioWriterSize(&w.cw, bufferBeforeChunkingSize)

	return w, nil
}

type checkConnErrorWriter struct {
	c *conn
}

func (w checkConnErrorWriter) Write(p []byte) (n int, err error) {
	n, err = w.c.rwc.Write(p)
	if err != nil && w.c.werr == nil {
		w.c.werr = err
	}
	return
}

type connReader struct {
	r io.Reader
}

func (cr *connReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	n, err = cr.r.Read(p)
	return
}

type chunkWriter struct {
	res *response
}

func (cw *chunkWriter) Write(p []byte) (n int, err error) {
	n, err = cw.res.conn.bufw.Write(p)
	if err != nil {
		cw.res.conn.rwc.Close()
	}
	return
}

func (cw *chunkWriter) flush() {
	cw.res.conn.bufw.Flush()
}

func (cw *chunkWriter) close() {
	// Nothing to do
}

// A response represents the server side of an HTTP response.
type response struct {
	conn *conn
	req  *Request // request for this response
	//reqBody       io.ReadCloser
	//wroteHeader   bool // reply header has been (logically) written
	//wroteContinue bool // 100 Continue response was written

	w  *bufio.Writer // buffers output in chunks to chunkWriter
	cw chunkWriter

	//// handlerHeader is the Header that Handlers get access to,
	//// which may be retained and mutated even after WriteHeader.
	//// handlerHeader is copied into cw.header at WriteHeader
	//// time, and privately mutated thereafter.
	//handlerHeader Header
	//calledHeader  bool // handler accessed handlerHeader via Header

	//written       int64 // number of bytes written in body
	//contentLength int64 // explicitly-declared Content-Length; or -1
	//status        int   // status code passed to WriteHeader

	//// close connection after this reply.  set on request and
	//// updated after response from handler if there's a
	//// "Connection: keep-alive" response header and a
	//// Content-Length.
	//closeAfterReply bool

	//// requestBodyLimitHit is set by requestTooLarge when
	//// maxBytesReader hits its max size. It is checked in
	//// WriteHeader, to make sure we don't consume the
	//// remaining request body to try to advance to the next HTTP
	//// request. Instead, when this is set, we stop reading
	//// subsequent requests on this connection and stop reading
	//// input from it.
	//requestBodyLimitHit bool

	//// trailers are the headers to be sent after the handler
	//// finishes writing the body.  This field is initialized from
	//// the Trailer response header when the response header is
	//// written.
	//trailers []string

	handlerDone atomicBool // set true when the handler exits

	//// Buffers for Date and Content-Length
	//dateBuf [len(TimeFormat)]byte
	//clenBuf [10]byte

	//// closeNotifyCh is non-nil once CloseNotify is called.
	//// Guarded by conn.mu
	//closeNotifyCh <-chan bool
}

type atomicBool int32

func (b *atomicBool) isSet() bool { return atomic.LoadInt32((*int32)(b)) != 0 }
func (b *atomicBool) setTrue()    { atomic.StoreInt32((*int32)(b), 1) }

func (w *response) Write(data []byte) (n int, err error) {
	if len(data) == 0 {
		return 0, nil
	}
	return w.w.Write(data)
}

func (w *response) finishRequest() {
	w.handlerDone.setTrue()

	w.w.Flush()
	putBufioWriter(w.w)
	w.cw.close()
	w.conn.bufw.Flush()
}

var (
	bufioReaderPool sync.Pool
	bufioWriterPool sync.Pool
)

func newBufioReader(r io.Reader) *bufio.Reader {
	if v := bufioReaderPool.Get(); v != nil {
		br := v.(*bufio.Reader)
		br.Reset(r)
		return br
	}

	return bufio.NewReader(r)
}

func newBufioWriterSize(w io.Writer, size int) *bufio.Writer {
	if v := bufioWriterPool.Get(); v != nil {
		bw := v.(*bufio.Writer)
		bw.Reset(w)
		return bw
	}

	return bufio.NewWriterSize(w, size)
}

func putBufioWriter(bw *bufio.Writer) {
	bw.Reset(nil)
	bufioWriterPool.Put(bw)
}
