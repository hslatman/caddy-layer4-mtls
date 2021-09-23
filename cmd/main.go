package main

import (
	cmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	_ "github.com/mholt/caddy-l4"

	_ "github.com/hslatman/caddy-l4-mtls"
)

func main() {
	cmd.Main()
}
