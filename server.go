// server.go — Live viewer for FB8 frames (8bpp) + mouse→touch bridge.
// Reads FB frames from a Unix socket (FB_STREAM_SOCK, default: /tmp/fbstream.sock)
// Sends touch commands (D/M/U) to a Unix socket (TOUCH_STREAM_SOCK, default: /tmp/touchstream.sock)
// UI with Ebiten: shows the live framebuffer; mouse/trackpad acts as a single-finger touch.
//
// Build:
//   go get github.com/hajimehoshi/ebiten/v2
//   go build -o server server.go
//
// Run:
//   First, run the server
//   HOST_MACHINE: sudo ./server
//   Then, start qumu to connect, run the initial init.d sripts by hand if needed
// 	 then start target bin with FB8+touch shims.
//   KINDLE (in qumu): LD_PRELOAD="/mnt/host/build/libfbshim.armhf.so:/mnt/host/build/libtouchshim.armhf.so" [bin]
//
// FB protocol (tolerant parser):
//   magic "FB8\x00" + header (24 or 28 bytes total *after* magic; we only read W/H as little-endian int32)
//   payload: W*H bytes (8-bit grayscale)
//
// Touch protocol (to touchshim):
//   Text lines: "D x y\n", "M x y\n", "U\n"
//   where x,y are pixel coords in FB space.
//
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/hajimehoshi/ebiten/v2"
)

var (
	fbSockPath    = getenv("FB_STREAM_SOCK", "/tmp/fbstream.sock")
	touchSockPath = getenv("TOUCH_STREAM_SOCK", "/tmp/touchstream.sock")
	viewW         = getenvInt("VIEW_W", 1272)
	viewH         = getenvInt("VIEW_H", 1696)
)

// Live framebuffer state
var (
	rgbaMu  sync.RWMutex
	rgbaImg *image.RGBA
	fbW, fbH int
	// drawRect is the rectangle inside the window where the framebuffer is drawn (for input mapping)
	drawRect image.Rectangle
)

func main() {
	fmt.Printf("[server] fb: %s  touch: %s  view: %dx%d\n", fbSockPath, touchSockPath, viewW, viewH)

	// Start FB reader
	go fbReader()

	// Start touch client (reconnect loop)
	touch := newTouchClient(touchSockPath)
	go touch.run()

	// Start UI
	ebiten.SetWindowSize(viewW, viewH)
	ebiten.SetWindowTitle("FB8 Viewer + Touch")
	ebiten.SetWindowResizingMode(ebiten.WindowResizingModeEnabled)

	g := &game{touch: touch}
	if err := ebiten.RunGame(g); err != nil {
		panic(err)
	}
}

// ------------ FB socket reader ------------
func fbReader() {
	for {
		if err := readOnce(); err != nil {
			fmt.Printf("[server] fb read error: %v; retrying in 1s\n", err)
			time.Sleep(1 * time.Second)
		}
	}
}

func readOnce() error {
	c, err := net.Dial("unix", fbSockPath)
	if err != nil {
		return err
	}
	defer c.Close()
	fmt.Println("[server] connected to FB socket")

	const magic = "FB8\x00"
	buf := make([]byte, 0, 1<<20)
	tmp := make([]byte, 64*1024)

	syncd := false
	var w, h int
	for {
		n, err := c.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			return err
		}
		for {
			// Try to find magic and parse one frame
			if !syncd {
				idx := bytes.Index(buf, []byte(magic))
				if idx < 0 {
					// keep buffer bounded
					if len(buf) > 1<<20 {
						buf = buf[len(buf)-(1<<19):]
					}
					break
				}
				// Drop up to magic
				if idx > 0 {
					buf = buf[idx:]
				}
				if len(buf) < 4 {
					break
				}
				// Need header after magic: 24 or 28 bytes
				if len(buf) < 4+24 {
					break
				}
				// Read width/height as little-endian int32 at offsets 4 and 8 after magic.
				hdr := buf[4:]
				if len(hdr) < 24 {
					break
				}
				w = int(int32(binary.LittleEndian.Uint32(hdr[0:4])))
				h = int(int32(binary.LittleEndian.Uint32(hdr[4:8])))
				if w <= 0 || h <= 0 || w*h > 16_000_000 {
					// bogus; drop first byte and resync
					buf = buf[1:]
					continue
				}
				// Skip header (stick to 24B for legacy; payload resync keeps us safe)
				var headLen = 24
				if len(buf) < 4+headLen {
					break
				}
				buf = buf[4+headLen:]
				syncd = true
			}

			need := w * h
			if len(buf) < need {
				break
			}
			payload := buf[:need]
			buf = buf[need:]
			syncd = false

			// Convert 8bpp -> RGBA and swap if W/H changed
			updateImage(w, h, payload)
		}
	}
}

func updateImage(w, h int, gray []byte) {
	rgbaMu.Lock()
	defer rgbaMu.Unlock()

	if rgbaImg == nil || rgbaImg.Bounds().Dx() != w || rgbaImg.Bounds().Dy() != h {
		rgbaImg = image.NewRGBA(image.Rect(0, 0, w, h))
		fbW, fbH = w, h
	}
	// Fast expand 8bpp to RGBA
	dst := rgbaImg.Pix
	for i, g := range gray {
		j := i * 4
		dst[j+0] = g
		dst[j+1] = g
		dst[j+2] = g
		dst[j+3] = 0xFF
	}
}

// ------------ ebiten game ------------
type game struct {
	touch     *touchClient
	mouseDown bool
}

func (g *game) Update() error {
	// Mouse -> touch bridge
	// Press or drag
	if ebiten.IsMouseButtonPressed(ebiten.MouseButtonLeft) {
		x, y := ebiten.CursorPosition()
		fx, fy, ok := windowToFB(x, y)
		if ok {
			if !g.mouseDown {
				g.touch.Down(fx, fy)
				g.mouseDown = true
			} else {
				g.touch.Move(fx, fy)
			}
		}
	} else {
		if g.mouseDown {
			g.touch.Up()
			g.mouseDown = false
		}
	}
	return nil
}

func (g *game) Draw(screen *ebiten.Image) {
	screen.Fill(color.RGBA{20, 20, 20, 255})

	rgbaMu.RLock()
	img := rgbaImg
	W := fbW
	H := fbH
	rgbaMu.RUnlock()

	if img == nil {
		return
	}

	// Compute destination rect with aspect-fit
	sw, sh := screen.Size()
	if W == 0 || H == 0 || sw == 0 || sh == 0 {
		return
	}
	scale := min(float64(sw)/float64(W), float64(sh)/float64(H))
	dw := int(float64(W)*scale + 0.5)
	dh := int(float64(H)*scale + 0.5)
	ox := (sw - dw) / 2
	oy := (sh - dh) / 2

	// Remember draw rect for input mapping
	drawRect = image.Rect(ox, oy, ox+dw, oy+dh)

	// Blit
	ebimg := ebiten.NewImageFromImage(img)
	op := &ebiten.DrawImageOptions{}
	op.GeoM.Scale(scale, scale)
	op.GeoM.Translate(float64(ox), float64(oy)) // <-- fixed
	screen.DrawImage(ebimg, op)
}

func (g *game) Layout(outsideWidth, outsideHeight int) (screenWidth, screenHeight int) {
	return outsideWidth, outsideHeight
}

// ------------ touch client ------------
type touchClient struct {
	path string
	mu   sync.Mutex
	conn net.Conn
	out  chan string
}

func newTouchClient(path string) *touchClient {
	return &touchClient{
		path: path,
		out:  make(chan string, 128),
	}
}

func (t *touchClient) run() {
	for {
		if err := t.loop(); err != nil {
			fmt.Printf("[touch] %v; reconnecting in 1s\n", err)
			time.Sleep(1 * time.Second)
		}
	}
}

func (t *touchClient) loop() error {
	c, err := net.Dial("unix", t.path)
	if err != nil {
		return err
	}
	fmt.Println("[touch] connected:", t.path)
	t.mu.Lock()
	t.conn = c
	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		if t.conn != nil {
			t.conn.Close()
			t.conn = nil
		}
		t.mu.Unlock()
	}()

	for {
		select {
		case line := <-t.out:
			if _, err := ioWriteString(c, line); err != nil {
				return err
			}
		}
	}
}

func (t *touchClient) send(format string, a ...any) {
	select {
	case t.out <- fmt.Sprintf(format, a...):
	default:
		// drop if channel full
	}
}

func (t *touchClient) Down(x, y int) { t.send("D %d %d\n", x, y) }
func (t *touchClient) Move(x, y int) { t.send("M %d %d\n", x, y) }
func (t *touchClient) Up()           { t.send("U\n") }

// ------------ helpers ------------
func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func getenvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// map window coords -> framebuffer pixel coords.
// Uses drawRect computed during Draw for aspect-fit mapping.
func windowToFB(wx, wy int) (fx, fy int, ok bool) {
	r := drawRect
	if wx < r.Min.X || wy < r.Min.Y || wx >= r.Max.X || wy >= r.Max.Y {
		return 0, 0, false
	}
	rgbaMu.RLock()
	W := fbW
	H := fbH
	rgbaMu.RUnlock()

	if W == 0 || H == 0 {
		return 0, 0, false
	}
	dw := r.Dx()
	dh := r.Dy()
	if dw <= 0 || dh <= 0 {
		return 0, 0, false
	}

	fx = (wx - r.Min.X) * W / dw
	fy = (wy - r.Min.Y) * H / dh
	// clamp
	if fx < 0 {
		fx = 0
	} else if fx >= W {
		fx = W - 1
	}
	if fy < 0 {
		fy = 0
	} else if fy >= H {
		fy = H - 1
	}
	return fx, fy, true
}

// lightweight WriteString to avoid importing bufio
func ioWriteString(c net.Conn, s string) (int, error) {
	n := 0
	for len(s) > 0 {
		m, err := c.Write([]byte(s))
		n += m
		if err != nil {
			return n, err
		}
		s = s[m:]
	}
	return n, nil
}
