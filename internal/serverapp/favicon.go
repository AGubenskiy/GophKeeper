package serverapp

import (
	"encoding/binary"
	"net/http"
	"strconv"
)

var faviconICOBytes = buildFaviconICO()

func handleFavicon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Content-Length", strconv.Itoa(len(faviconICOBytes)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(faviconICOBytes)
}

func buildFaviconICO() []byte {
	const (
		width        = 16
		height       = 16
		headerBytes  = 40
		bitmapBytes  = width * height * 4
		maskRowBytes = ((width + 31) / 32) * 4
		maskBytes    = maskRowBytes * height
		bytesInRes   = headerBytes + bitmapBytes + maskBytes
		imageOffset  = 22
	)

	out := make([]byte, 0, imageOffset+bytesInRes)
	put16 := func(value uint16) {
		var buffer [2]byte
		binary.LittleEndian.PutUint16(buffer[:], value)
		out = append(out, buffer[:]...)
	}
	put32 := func(value uint32) {
		var buffer [4]byte
		binary.LittleEndian.PutUint32(buffer[:], value)
		out = append(out, buffer[:]...)
	}

	put16(0)
	put16(1)
	put16(1)

	out = append(out, byte(width), byte(height), 0, 0)
	put16(1)
	put16(32)
	put32(bytesInRes)
	put32(imageOffset)

	put32(headerBytes)
	put32(width)
	put32(height * 2)
	put16(1)
	put16(32)
	put32(0)
	put32(bitmapBytes)
	put32(0)
	put32(0)
	put32(0)
	put32(0)

	for y := height - 1; y >= 0; y-- {
		for x := 0; x < width; x++ {
			red, green, blue := faviconPixel(x, y, width, height)
			out = append(out, blue, green, red, 0xff)
		}
	}
	out = append(out, make([]byte, maskBytes)...)
	return out
}

func faviconPixel(x, y, width, height int) (byte, byte, byte) {
	if x == 0 || y == 0 || x == width-1 || y == height-1 {
		return 17, 24, 39
	}
	if x < width/2 {
		return 20, 184, 166
	}
	return 96, 165, 250
}
