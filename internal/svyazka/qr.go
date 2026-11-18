package svyazka

import (
	"errors"
	"fmt"
	"strings"
)

// A small QR code encoder (byte mode, error correction level M, versions
// 1–10: up to 213 bytes), enough for a subscription link, so a phone app can
// add it by scanning the screen. Follows ISO/IEC 18004 the way Project
// Nayuki's reference implementation lays it out.

var (
	qrECCPerBlock = [11]int{0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26} // level M
	qrBlocks      = [11]int{0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5}
)

// QR is a square of modules; true is dark.
type QR struct {
	Size    int
	modules [][]bool
	fn      [][]bool
}

// Dark reports the module at column x, row y.
func (q *QR) Dark(x, y int) bool { return q.modules[y][x] }

func qrRawModules(ver int) int {
	r := (16*ver+128)*ver + 64
	if ver >= 2 {
		n := ver/7 + 2
		r -= (25*n-10)*n - 55
		if ver >= 7 {
			r -= 36
		}
	}
	return r
}

func qrDataCodewords(ver int) int {
	return qrRawModules(ver)/8 - qrECCPerBlock[ver]*qrBlocks[ver]
}

// EncodeQR makes a QR code for text.
func EncodeQR(text string) (*QR, error) {
	data := []byte(text)
	ver := 0
	for v := 1; v <= 10; v++ {
		countBits := 8
		if v >= 10 {
			countBits = 16
		}
		if 4+countBits+8*len(data) <= qrDataCodewords(v)*8 {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, errors.New("слишком длинный текст для QR-кода")
	}
	// bit stream: mode, length, bytes, terminator, padding
	var bits []bool
	put := func(v, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, v>>i&1 == 1)
		}
	}
	put(0b0100, 4)
	if ver >= 10 {
		put(len(data), 16)
	} else {
		put(len(data), 8)
	}
	for _, b := range data {
		put(int(b), 8)
	}
	capBits := qrDataCodewords(ver) * 8
	put(0, min(4, capBits-len(bits)))
	put(0, (8-len(bits)%8)%8)
	for pad := 0xEC; len(bits) < capBits; pad ^= 0xEC ^ 0x11 {
		put(pad, 8)
	}
	codewords := make([]byte, len(bits)/8)
	for i, b := range bits {
		if b {
			codewords[i>>3] |= 1 << (7 - i&7)
		}
	}

	q := &QR{Size: ver*4 + 17}
	q.modules = make([][]bool, q.Size)
	q.fn = make([][]bool, q.Size)
	for i := range q.modules {
		q.modules[i] = make([]bool, q.Size)
		q.fn[i] = make([]bool, q.Size)
	}
	q.drawFunctionPatterns(ver)
	q.drawCodewords(qrAddECC(codewords, ver))

	best, bestPenalty := 0, -1
	for mask := 0; mask < 8; mask++ {
		q.applyMask(mask)
		q.drawFormat(mask)
		if p := q.penalty(); bestPenalty < 0 || p < bestPenalty {
			best, bestPenalty = mask, p
		}
		q.applyMask(mask) // undo (XOR)
	}
	q.applyMask(best)
	q.drawFormat(best)
	return q, nil
}

func (q *QR) set(x, y int, dark bool) {
	q.modules[y][x] = dark
	q.fn[y][x] = true
}

func (q *QR) drawFunctionPatterns(ver int) {
	for i := 0; i < q.Size; i++ {
		q.set(6, i, i%2 == 0)
		q.set(i, 6, i%2 == 0)
	}
	for _, c := range [][2]int{{3, 3}, {q.Size - 4, 3}, {3, q.Size - 4}} {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				x, y := c[0]+dx, c[1]+dy
				if x < 0 || y < 0 || x >= q.Size || y >= q.Size {
					continue
				}
				d := max(abs(dx), abs(dy))
				q.set(x, y, d != 2 && d != 4)
			}
		}
	}
	pos := qrAlignment(ver)
	for i, x := range pos {
		for j, y := range pos {
			if i == 0 && j == 0 || i == 0 && j == len(pos)-1 || i == len(pos)-1 && j == 0 {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					q.set(x+dx, y+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	q.drawFormat(0) // reserve; real bits are drawn after masking
	if ver >= 7 {
		rem := ver
		for i := 0; i < 12; i++ {
			rem = rem<<1 ^ (rem>>11)*0x1F25
		}
		v := ver<<12 | rem
		for i := 0; i < 18; i++ {
			dark := v>>i&1 == 1
			a, b := q.Size-11+i%3, i/3
			q.set(a, b, dark)
			q.set(b, a, dark)
		}
	}
}

func qrAlignment(ver int) []int {
	if ver == 1 {
		return nil
	}
	n := ver/7 + 2
	step := (ver*8 + n*3 + 5) / (n*4 - 4) * 2
	out := make([]int, n)
	out[0] = 6
	for i, p := n-1, ver*4+10; i >= 1; i, p = i-1, p-step {
		out[i] = p
	}
	return out
}

func (q *QR) drawFormat(mask int) {
	data := 0<<3 | mask // level M has format bits 00
	rem := data
	for i := 0; i < 10; i++ {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	bits := (data<<10 | rem) ^ 0x5412
	bit := func(i int) bool { return bits>>i&1 == 1 }
	for i := 0; i <= 5; i++ {
		q.set(8, i, bit(i))
	}
	q.set(8, 7, bit(6))
	q.set(8, 8, bit(7))
	q.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		q.set(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		q.set(q.Size-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		q.set(8, q.Size-15+i, bit(i))
	}
	q.set(8, q.Size-8, true)
}

func qrAddECC(data []byte, ver int) []byte {
	nBlocks, eccLen := qrBlocks[ver], qrECCPerBlock[ver]
	raw := qrRawModules(ver) / 8
	nShort := nBlocks - raw%nBlocks
	shortLen := raw / nBlocks
	div := rsDivisor(eccLen)
	var blocks [][]byte
	k := 0
	for i := 0; i < nBlocks; i++ {
		n := shortLen - eccLen
		if i >= nShort {
			n++
		}
		dat := append([]byte{}, data[k:k+n]...)
		k += n
		ecc := rsRemainder(dat, div)
		if i < nShort {
			dat = append(dat, 0)
		}
		blocks = append(blocks, append(dat, ecc...))
	}
	var out []byte
	for i := range blocks[0] {
		for j, b := range blocks {
			if i != shortLen-eccLen || j >= nShort {
				out = append(out, b[i])
			}
		}
	}
	return out
}

func gfMul(x, y byte) byte {
	var z int
	for i := 7; i >= 0; i-- {
		z = z<<1 ^ (z>>7)*0x11D
		z ^= int(y>>i&1) * int(x)
	}
	return byte(z)
}

func rsDivisor(degree int) []byte {
	res := make([]byte, degree)
	res[degree-1] = 1
	root := byte(1)
	for i := 0; i < degree; i++ {
		for j := range res {
			res[j] = gfMul(res[j], root)
			if j+1 < len(res) {
				res[j] ^= res[j+1]
			}
		}
		root = gfMul(root, 2)
	}
	return res
}

func rsRemainder(data, div []byte) []byte {
	res := make([]byte, len(div))
	for _, b := range data {
		f := b ^ res[0]
		copy(res, res[1:])
		res[len(res)-1] = 0
		for i, c := range div {
			res[i] ^= gfMul(c, f)
		}
	}
	return res
}

func (q *QR) drawCodewords(data []byte) {
	i := 0
	for right := q.Size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < q.Size; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = q.Size - 1 - vert
				}
				if !q.fn[y][x] && i < len(data)*8 {
					q.modules[y][x] = data[i>>3]>>(7-i&7)&1 == 1
					i++
				}
			}
		}
	}
}

func (q *QR) applyMask(mask int) {
	for y := 0; y < q.Size; y++ {
		for x := 0; x < q.Size; x++ {
			if q.fn[y][x] {
				continue
			}
			var inv bool
			switch mask {
			case 0:
				inv = (x+y)%2 == 0
			case 1:
				inv = y%2 == 0
			case 2:
				inv = x%3 == 0
			case 3:
				inv = (x+y)%3 == 0
			case 4:
				inv = (x/3+y/2)%2 == 0
			case 5:
				inv = x*y%2+x*y%3 == 0
			case 6:
				inv = (x*y%2+x*y%3)%2 == 0
			case 7:
				inv = ((x+y)%2+x*y%3)%2 == 0
			}
			if inv {
				q.modules[y][x] = !q.modules[y][x]
			}
		}
	}
}

// penalty scores how hard the symbol is to read (lower is better).
func (q *QR) penalty() int {
	n := q.Size
	p := 0
	line := func(get func(i int) bool) {
		run := 1
		for i := 1; i <= n; i++ {
			if i < n && get(i) == get(i-1) {
				run++
				continue
			}
			if run >= 5 {
				p += 3 + run - 5
			}
			run = 1
		}
		pat := []bool{true, false, true, true, true, false, true}
		for i := 0; i+7 <= n; i++ {
			match := true
			for k, v := range pat {
				if get(i+k) != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}
			light := func(from, to int) bool {
				for k := from; k < to; k++ {
					if k >= 0 && k < n && get(k) {
						return false
					}
				}
				return true
			}
			if light(i-4, i) || light(i+7, i+11) {
				p += 40
			}
		}
	}
	for y := 0; y < n; y++ {
		line(func(i int) bool { return q.modules[y][i] })
	}
	for x := 0; x < n; x++ {
		line(func(i int) bool { return q.modules[i][x] })
	}
	dark := 0
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			c := q.modules[y][x]
			if c {
				dark++
			}
			if x+1 < n && y+1 < n && c == q.modules[y][x+1] && c == q.modules[y+1][x] && c == q.modules[y+1][x+1] {
				p += 3
			}
		}
	}
	total := n * n
	k := (abs(dark*20-total*10)+total-1)/total - 1
	return p + k*10
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// SVG draws the code with a four-module quiet zone.
func (q *QR) SVG() string {
	var b strings.Builder
	side := q.Size + 8
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges">`, side, side)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, side, side)
	for y := 0; y < q.Size; y++ {
		for x := 0; x < q.Size; x++ {
			if q.modules[y][x] {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+4, y+4)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}
