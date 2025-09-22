package staticembed

import "embed"

//go:embed *.html consent.js styles.css offers.js bulma.min.css
var FS embed.FS
