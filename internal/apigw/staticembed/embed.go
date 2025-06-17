package staticembed

import "embed"

//go:embed index.html consent.js consent.css
var FS embed.FS
