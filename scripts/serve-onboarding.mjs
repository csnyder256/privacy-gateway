import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, join } from "node:path";

const root = new URL("../src/privacy_gateway/static/", import.meta.url).pathname;
const types = { ".css": "text/css", ".html": "text/html", ".js": "text/javascript", ".svg": "image/svg+xml" };

createServer(async (request, response) => {
  const pathname = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
  const relative = pathname === "/" ? "index.html" : pathname.replace(/^\/assets\//u, "").replace(/^\//u, "");
  if (!/^[A-Za-z0-9._-]+$/u.test(relative)) {
    response.writeHead(404).end();
    return;
  }
  const path = join(root, relative);
  try {
    const details = await stat(path);
    if (!details.isFile()) throw new Error("not a file");
    response.writeHead(200, { "content-type": types[extname(path)] ?? "application/octet-stream" });
    createReadStream(path).pipe(response);
  } catch {
    response.writeHead(404).end();
  }
}).listen(4173, "127.0.0.1");
