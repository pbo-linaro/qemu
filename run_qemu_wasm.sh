#!/usr/bin/env bash

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "usage: data_dir path/to/qemu.js args..."
    exit 1
fi

if [ ! -d emscripten ]; then
    git clone https://github.com/emscripten-core/emscripten/ --depth 1
fi

data_dir=$1; shift
qemu=$1; shift
./emscripten/tools/file_packager.py pack.data --preload "$data_dir" > load.js

params=""
for p in "$@"; do
    params="$params '$p',"
done

# https://github.com/mame/xterm-pty
cat > index.html << EOF
<!DOCTYPE html>
<html>
  <head>
    <link
      rel="stylesheet"
      href="https://unpkg.com/@xterm/xterm/css/xterm.css"
    />
  </head>
  <body>
    <div id="terminal"></div>
    <script src="./load.js"></script>
    <script type="module">
      import "https://unpkg.com/@xterm/xterm/lib/xterm.js";
      import { openpty } from "https://unpkg.com/xterm-pty/index.mjs";
      import initEmscripten from "$qemu";

      var xterm = new Terminal();
      xterm.open(document.getElementById("terminal"));

      // Create master/slave objects
      const { master, slave } = openpty();

      // Connect the master object to xterm.js
      xterm.loadAddon(master);

      Module.pty = slave;
      Module['arguments'] = [$params]
      await initEmscripten(Module);
    </script>
  </body>
</html>
EOF

cat > server.py << EOF
#!/usr/bin/env python3
from http.server import HTTPServer, SimpleHTTPRequestHandler, test
import sys

class CORSRequestHandler (SimpleHTTPRequestHandler):
    def end_headers (self):
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
        self.send_header('Cross-Origin-Resource-Policy', 'same-site')
        SimpleHTTPRequestHandler.end_headers(self)

if __name__ == '__main__':
    test(CORSRequestHandler, HTTPServer, port=8000)
EOF

echo "http://localhost:8000"
python3 server.py > /dev/null
