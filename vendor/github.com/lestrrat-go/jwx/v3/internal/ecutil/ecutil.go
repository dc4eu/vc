// Package ecutil defines tools that help with elliptic curve related
// computation
package ecutil

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

const (
	// size of buffer that needs to be allocated for EC521 curve
	ec521BufferSize = 66 // (521 / 8) + 1
)

var ecpointBufferPool = sync.Pool{
	New: func() interface{} {
		// In most cases the curve bit size will be less than this length
		// so allocate the maximum, and keep reusing
		buf := make([]byte, 0, ec521BufferSize)
		return &buf
	},
}

func getCrvFixedBuffer(size int) []byte {
	//nolint:forcetypeassert
	buf := *(ecpointBufferPool.Get().(*[]byte))
	if size > ec521BufferSize && cap(buf) < size {
		buf = append(buf, make([]byte, size-cap(buf))...)
	}
	return buf[:size]
}

// ReleaseECPointBuffer releases the []byte buffer allocated.
func ReleaseECPointBuffer(buf []byte) {
	buf = buf[:cap(buf)]
	buf[0] = 0x0
	for i := 1; i < len(buf); i *= 2 {
		copy(buf[i:], buf[:i])
	}
	buf = buf[:0]
	ecpointBufferPool.Put(&buf)
}

func CalculateKeySize(crv elliptic.Curve) int {
	// We need to create a buffer that fits the entire curve.
	// If the curve size is 66, that fits in 9 bytes. If the curve
	// size is 64, it fits in 8 bytes.
	bits := crv.Params().BitSize

	// For most common cases we know before hand what the byte length
	// is going to be. optimize
	var inBytes int
	switch bits {
	case 224, 256, 384: // TODO: use constant?
		inBytes = bits / 8
	case 521:
		inBytes = ec521BufferSize
	default:
		inBytes = bits / 8
		if (bits % 8) != 0 {
			inBytes++
		}
	}

	return inBytes
}

// AllocECPointBuffer allocates a buffer for the given point in the given
// curve. This buffer should be released using the ReleaseECPointBuffer
// function.
func AllocECPointBuffer(v *big.Int, crv elliptic.Curve) []byte {
	buf := getCrvFixedBuffer(CalculateKeySize(crv))
	v.FillBytes(buf)
	return buf
}
